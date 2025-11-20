#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sync Adapter 微服务

用途：为客户端提供一个独立的云端存储空间（物理路径为 `data/server_storage/sync_uploads`），
但复用同一份 SQLite 数据库 `file_server.db` 的 `files` 表以共享元数据。

注意：Java 服务 `HttpFileServer.java` 不需要被修改。客户端可以把 `Module/config.py` 中的
`server.base_url` 改为本适配器地址（默认 http://localhost:4000），即可将同步流量发送到本服务。

安全：如果环境变量 `JWT_SECRET` 可用，服务将尝试解析传入的 `Authorization: Bearer <token>`
以获取 `sub`（用户 id）作为上传者；否则默认使用 uploader_id=1（admin）。

使用：
  python sync_adapter.py

依赖：Flask, PyJWT
"""
import os
import sqlite3
import hashlib
import uuid
import shutil
from pathlib import Path
from flask import Flask, request, jsonify, send_file
import jwt
from datetime import datetime
try:
    from cryptography.fernet import Fernet
    HAVE_FERNET = True
except Exception:
    HAVE_FERNET = False
ENCRYPTION_KEY = os.environ.get('SYNC_ENCRYPTION_KEY')
import gzip
import threading

# 配置
PORT = int(os.environ.get("SYNC_ADAPTER_PORT", "4000"))
BASE_DIR = Path(__file__).parent.resolve()
# newbe 目录是项目根，Sync 在其中
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
# 将 server_storage 移动到 newbe/data 下
BASE_STORAGE = DATA_DIR / "server_storage"
SYNC_UPLOAD_DIR = BASE_STORAGE / "sync_uploads"
BLOCKS_DIR = BASE_STORAGE / "blocks"
RECYCLE_DIR = BASE_DIR / "recycle_bin_sync"
DB_PATH = BASE_DIR / "file_server.db"
JWT_SECRET = os.environ.get("JWT_SECRET", "x8V2#zQ9!pL7@wK3$rT5*yB1&mN4%vF6^gH8(jU0)tR2")

# ensure directories
SYNC_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
BLOCKS_DIR.mkdir(parents=True, exist_ok=True)
RECYCLE_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

# Print resolved paths for debugging and to avoid cwd-related surprises
print(f"Sync Adapter paths: PROJECT_ROOT={PROJECT_ROOT}, BASE_DIR={BASE_DIR}, DATA_DIR={DATA_DIR}, BASE_STORAGE={BASE_STORAGE}")
print(f"SYNC_UPLOAD_DIR={SYNC_UPLOAD_DIR}, BLOCKS_DIR={BLOCKS_DIR}, DB_PATH={DB_PATH}")

def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def compute_md5_bytes(data: bytes) -> str:
    m = hashlib.md5()
    m.update(data)
    return m.hexdigest()

def compute_md5_file(path: Path) -> str:
    m = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            m.update(chunk)
    return m.hexdigest()

def decode_token(token: str):
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"verify_exp": False})
        return payload
    except Exception:
        return None

def ensure_tables():
    # assume Java already created tables; if not, create minimal files table compatible with Java
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        file_type TEXT,
        filepath TEXT UNIQUE NOT NULL,
        filesize INTEGER NOT NULL,
        md5 TEXT NOT NULL,
        uploader_id INTEGER NOT NULL,
        parent_id INTEGER,
        upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_deleted INTEGER DEFAULT 0,
        delete_time DATETIME
    )
    """)
    conn.commit()
    conn.close()

ensure_tables()

# 尝试导入并准备数据库维护守护线程（每隔一段时间清理不存在的 DB 记录）
try:
    from maintain_db import monitor_and_clean_db
    def _start_db_maintainer(interval: int = 5):
        t = threading.Thread(target=monitor_and_clean_db, kwargs={'db_path': DB_PATH, 'storage_roots': [SYNC_UPLOAD_DIR, BASE_STORAGE / 'uploads'], 'interval': interval}, daemon=True)
        t.start()
except Exception as _e:
    # 若无法导入维护脚本则继续运行适配器但不启动维护线程
    def _start_db_maintainer(interval: int = 5):
        print('未找到 maintain_db.py，跳过 DB 维护线程启动')

@app.route('/api/files/upload', methods=['POST'])
def upload():
    # 支持 multipart/form-data: 'file' 字段；并可携带 form 字段 'relativePath' 和 'filename'
    token = None
    auth = request.headers.get('Authorization')
    if auth and auth.startswith('Bearer '):
        token = auth[7:]
    payload = decode_token(token)
    uploader_id = int(payload.get('sub')) if payload and payload.get('sub') else 1
    username = payload.get('username') if payload and payload.get('username') else f'user_{uploader_id}'

    if 'file' not in request.files:
        return jsonify({'success': False, 'message': '缺少 file 字段'}), 400
    f = request.files['file']
    rel = request.form.get('relativePath') or request.form.get('relativePath'.lower()) or f.filename
    # 保证安全文件名（简单处理）
    filename = request.form.get('filename') or f.filename

    # 构建目标路径：为每个用户单独创建目录（用户名）以保证私密性
    user_dir = SYNC_UPLOAD_DIR / username
    user_dir.mkdir(parents=True, exist_ok=True)
    rel_path = Path(rel)
    target_path = user_dir / rel_path
    target_path.parent.mkdir(parents=True, exist_ok=True)

    # 如果上传的是文件流，保存到临时文件
    saved_name = str(int(datetime.utcnow().timestamp() * 1000)) + "_" + str(uuid.uuid4()) + Path(filename).suffix
    final_path = target_path
    # 如果 rel 指向文件名而非包含目录，target_path may be just filename under sync dir
    try:
        f.save(str(final_path))
    except Exception:
        # fallback: save under generated name
        final_path = SYNC_UPLOAD_DIR / saved_name
        f.save(str(final_path))

    # 先计算原始文件的 md5（对未压缩文件），然后将文件压缩存储到服务器以节省空间
    size = final_path.stat().st_size
    md5 = compute_md5_file(final_path)
    compressed_path = final_path.with_name(final_path.name + '.gz')
    try:
        with open(final_path, 'rb') as rf:
            data = rf.read()
        with open(compressed_path, 'wb') as wf:
            wf.write(gzip.compress(data))
        # 删除原始文件，保留压缩后的文件
        try:
            final_path.unlink()
        except Exception:
            pass
        final_path = compressed_path
        size = final_path.stat().st_size
    except Exception as e:
        # 如果压缩过程出错，继续使用原始文件
        print('压缩失败，保留原始文件：', e)

    # 写入数据库记录（filepath 使用绝对路径），记录 uploader_id 与 username 由数据库现有字段承担 uploader_id
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO files (filename, file_type, filepath, filesize, md5, uploader_id, parent_id, upload_time, is_deleted) VALUES (?, ?, ?, ?, ?, ?, NULL, CURRENT_TIMESTAMP, 0)",
                    (filename, 'file', str(final_path), size, md5, uploader_id))
        conn.commit()
        file_id = cur.lastrowid
    except sqlite3.IntegrityError:
        # 可能已经存在相同 filepath，尝试更新记录
        cur.execute("SELECT id FROM files WHERE filepath = ?", (str(final_path),))
        row = cur.fetchone()
        if row:
            file_id = row['id']
        else:
            file_id = None
    finally:
        conn.close()

    # 返回的 relativePath 以用户目录为根，方便客户端显示和后续 delete 定位
    try:
        rel_for_user = str(final_path.relative_to(user_dir))
    except Exception:
        rel_for_user = final_path.name
    return jsonify({'success': True, 'data': {'id': file_id, 'filename': filename, 'relativePath': rel_for_user, 'username': username}})


@app.route('/api/files/check', methods=['GET'])
def file_check():
    """检查服务器是否已有给定文件指纹（hash）。返回 {'exists': bool, 'id': id or None} """
    h = request.args.get('hash')
    if not h:
        return jsonify({'success': False, 'message': '缺少 hash 参数'}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM files WHERE md5 = ? AND is_deleted = 0 LIMIT 1", (h,))
    row = cur.fetchone()
    conn.close()
    if row:
        return jsonify({'success': True, 'exists': True, 'id': row['id']})
    return jsonify({'success': True, 'exists': False, 'id': None})


@app.route('/api/blocks/check', methods=['POST'])
def blocks_check():
    data = request.get_json(force=True, silent=True) or {}
    hashes = data.get('hashes') or []
    missing = []
    for h in hashes:
        p = BLOCKS_DIR / h
        if not p.exists():
            missing.append(h)
    print(f"blocks_check: received {len(hashes)} hashes, missing {len(missing)}")
    return jsonify({'success': True, 'missing': missing})


@app.route('/api/blocks/upload', methods=['POST'])
def blocks_upload():
    # multipart: 'chunk' file and 'hash' form field
    h = request.form.get('hash')
    if not h:
        return jsonify({'success': False, 'message': '缺少 hash 字段'}), 400
    if 'chunk' not in request.files:
        return jsonify({'success': False, 'message': '缺少 chunk 文件'}), 400
    chunk = request.files['chunk']
    target = BLOCKS_DIR / h
    try:
        if not target.exists():
            chunk.save(str(target))
            print(f"blocks_upload: saved block {h} size={target.stat().st_size}")
        else:
            print(f"blocks_upload: block {h} already exists")
        return jsonify({'success': True, 'hash': h})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/files/assemble', methods=['POST'])
def files_assemble():
    """根据块列表组装文件（块为已压缩数据的连续片段），将组装后的压缩文件保存到用户目录并在 files 表中写入记录。
    请求 JSON: {relativePath, filename, chunks: [hash1,...], file_hash}
    """
    data = request.get_json(force=True, silent=True) or {}
    rel = data.get('relativePath')
    filename = data.get('filename')
    chunks = data.get('chunks') or []
    file_hash = data.get('file_hash')
    token = None
    auth = request.headers.get('Authorization')
    if auth and auth.startswith('Bearer '):
        token = auth[7:]
    payload = decode_token(token)
    uploader_id = int(payload.get('sub')) if payload and payload.get('sub') else 1
    username = payload.get('username') if payload and payload.get('username') else f'user_{uploader_id}'

    # 必须提供 relativePath, filename, file_hash；chunks 可为空（若 file_hash 已存在，将直接创建指针记录）
    if not rel or not filename or not file_hash:
        return jsonify({'success': False, 'message': '参数不完整'}), 400

    user_dir = SYNC_UPLOAD_DIR / username
    user_dir.mkdir(parents=True, exist_ok=True)
    target_path = user_dir / Path(rel)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    # 组装为压缩文件（直接按块顺序拼接）
    try:
        # 若服务器上已有相同 file_hash 的文件，则直接为该用户创建新记录（指针），避免重复组装
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, filepath FROM files WHERE md5 = ? AND is_deleted = 0 LIMIT 1", (file_hash,))
        exist_row = cur.fetchone()
        if exist_row:
            existing_path = Path(exist_row['filepath'])
            print(f"files/assemble: found existing file with md5={file_hash}, existing_path={existing_path}, preparing pointer for uploader={uploader_id} username={username} filename={filename}")
            # 目标路径在该用户目录下（保留原始文件名并以 .gz 存储）
            target_user_path = user_dir / Path(rel)
            target_user_path.parent.mkdir(parents=True, exist_ok=True)
            # 确保目标为压缩文件名（existing_path 预计为 .gz）
            if not target_user_path.name.endswith('.gz'):
                target_user_path = target_user_path.with_name(target_user_path.name + '.gz')

            # 尝试创建硬链接以避免复制；若失败则回退为复制
            try:
                if existing_path.exists():
                    try:
                        os.link(str(existing_path), str(target_user_path))
                    except Exception:
                        # Windows / 权限或跨分区可能不支持硬链，回退到拷贝
                        import shutil
                        shutil.copy2(str(existing_path), str(target_user_path))
                else:
                    # 如果原始文件路径不存在，则仍尝试创建记录指向原始路径（兼容旧数据）
                    target_user_path = existing_path

                size = target_user_path.stat().st_size if target_user_path.exists() else 0
                try:
                    cur.execute(
                        "INSERT INTO files (filename, file_type, filepath, filesize, md5, uploader_id, parent_id, upload_time, is_deleted) VALUES (?, ?, ?, ?, ?, ?, NULL, CURRENT_TIMESTAMP, 0)",
                        (filename, 'file', str(target_user_path), size, file_hash, uploader_id)
                    )
                    conn.commit()
                    new_id = cur.lastrowid
                except sqlite3.IntegrityError:
                    # 若仍冲突（极少发生），返回已存在记录 id
                    cur.execute("SELECT id FROM files WHERE filepath = ?", (str(target_user_path),))
                    row = cur.fetchone()
                    new_id = row['id'] if row else exist_row['id']
            except Exception as e:
                # 出错时回退为返回已存在记录 id
                print(f"files/assemble: pointer creation failed, error={e}")
                new_id = exist_row['id']
            conn.close()
            print(f"files/assemble: pointer creation result id={new_id}, filepath={target_user_path}")
            return jsonify({'success': True, 'id': new_id})

        # 否则，按块组装。
        # 如果配置了加密，准备解密器
        fernet = None
        if ENCRYPTION_KEY and HAVE_FERNET:
            try:
                fernet = Fernet(ENCRYPTION_KEY)
            except Exception:
                fernet = None

        # 先在临时文件里按顺序写入（解密后为原始明文）
        tmp_path = target_path.with_suffix('.assembling')
        try:
            with open(tmp_path, 'wb') as out:
                for h in chunks:
                    bpath = BLOCKS_DIR / h
                    if not bpath.exists():
                        conn.close()
                        try:
                            tmp_path.unlink()
                        except Exception:
                            pass
                        return jsonify({'success': False, 'message': f'缺失块 {h}'}), 400
                    with open(bpath, 'rb') as bf:
                        data = bf.read()
                        if fernet:
                            try:
                                data = fernet.decrypt(data)
                            except Exception:
                                pass
                        out.write(data)

            # 压缩临时组装文件为最终存储文件（gzip），节省磁盘空间
            compressed_final = target_path.with_name(target_path.name + '.gz')
            with open(tmp_path, 'rb') as rf:
                raw = rf.read()
            with open(compressed_final, 'wb') as wf:
                wf.write(gzip.compress(raw))
            try:
                tmp_path.unlink()
            except Exception:
                pass

            # 写入数据库：filepath 使用压缩后的绝对路径，md5 字段存储 file_hash（客户端使用 sha256）
            size = compressed_final.stat().st_size
            try:
                cur.execute("INSERT INTO files (filename, file_type, filepath, filesize, md5, uploader_id, parent_id, upload_time, is_deleted) VALUES (?, ?, ?, ?, ?, ?, NULL, CURRENT_TIMESTAMP, 0)",
                            (filename, 'file', str(compressed_final), size, file_hash, uploader_id))
                conn.commit()
                file_id = cur.lastrowid
            except sqlite3.IntegrityError:
                cur.execute("SELECT id FROM files WHERE filepath = ?", (str(compressed_final),))
                row = cur.fetchone()
                file_id = row['id'] if row else None
            finally:
                conn.close()
            return jsonify({'success': True, 'id': file_id})
        except Exception as e:
            conn.close()
            try:
                tmp_path.unlink()
            except Exception:
                pass
            return jsonify({'success': False, 'message': str(e)}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/files', methods=['GET'])
def list_files():
    token = None
    auth = request.headers.get('Authorization')
    if auth and auth.startswith('Bearer '):
        token = auth[7:]
    payload = decode_token(token)
    uploader_id = int(payload.get('sub')) if payload and payload.get('sub') else 1

    conn = get_db()
    cur = conn.cursor()
    # 查询属于该用户（uploader_id）的文件记录
    cur.execute("SELECT id, filename, filesize, md5, filepath, upload_time FROM files WHERE uploader_id = ? AND is_deleted = 0 ORDER BY upload_time DESC", (uploader_id,))
    rows = cur.fetchall()
    result = []
    for r in rows:
        fp = Path(r['filepath'])
        # 计算相对于用户目录的路径，如果不在用户目录则返回文件名
        try:
            # rel 形式可能为 'username/...'，我们希望返回相对于 username 的路径并同时返回 username
            rel = str(fp.relative_to(SYNC_UPLOAD_DIR))
            parts = Path(rel).parts
            if len(parts) >= 2:
                username_part = parts[0]
                rel_for_user = str(Path(*parts[1:]))
            else:
                username_part = parts[0] if parts else ''
                rel_for_user = parts[-1] if parts else fp.name
        except Exception:
            username_part = ''
            rel_for_user = fp.name
        result.append({'id': r['id'], 'filename': r['filename'], 'filesize': r['filesize'], 'md5': r['md5'], 'relativePath': rel_for_user, 'username': username_part})
    conn.close()
    return jsonify({'success': True, 'data': result})


@app.route('/api/files/download', methods=['GET'])
def download():
    file_id = request.args.get('fileId')
    if not file_id:
        return jsonify({'success': False, 'message': '缺少 fileId 参数'}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT filename, filepath, filesize FROM files WHERE id = ? AND is_deleted = 0", (file_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({'success': False, 'message': '未找到文件或已被删除'}), 404
    path = Path(row['filepath'])
    if not path.exists():
        return jsonify({'success': False, 'message': '物理文件不存在'}), 404
    return send_file(str(path), as_attachment=True, download_name=row['filename'])


@app.route('/api/files/delete', methods=['POST'])
def delete():
    data = request.get_json(force=True, silent=True) or {}
    relative = data.get('relativePath') or data.get('relative_path')
    if not relative:
        return jsonify({'success': False, 'message': '缺少 relativePath'}), 400

    # 尝试定位文件（以 SYNC_UPLOAD_DIR 相对路径匹配）
    target = SYNC_UPLOAD_DIR / Path(relative)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, filepath FROM files WHERE filepath = ? OR filepath LIKE ? LIMIT 1", (str(target), f"%{relative}"))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'message': '未找到对应文件记录'}), 404
    file_id = row['id']
    filepath = Path(row['filepath'])
    # 移动物理文件至回收站
    try:
        if filepath.exists():
            dest = RECYCLE_DIR / (filepath.name)
            shutil.move(str(filepath), str(dest))
        # 标记数据库为已删除
        cur.execute("UPDATE files SET is_deleted = 1, delete_time = CURRENT_TIMESTAMP WHERE id = ?", (file_id,))
        conn.commit()
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': str(e)}), 500
    conn.close()
    return jsonify({'success': True, 'message': '删除成功'})


if __name__ == '__main__':
    print(f"启动 Sync Adapter，端口={PORT}，上传目录={SYNC_UPLOAD_DIR}")
    # 启动数据库维护守护线程（若可用）
    try:
        _start_db_maintainer(interval=5)
    except Exception:
        pass
    app.run(host='0.0.0.0', port=PORT, debug=False)
