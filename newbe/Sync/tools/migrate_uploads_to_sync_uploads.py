#!/usr/bin/env python3
# -*- coding:utf-8 -*-
"""
迁移脚本：将 file_server.db 中指向 `data/server_storage/uploads` 的记录
移动到 `data/server_storage/sync_uploads/{username}/...` 并更新数据库 filepath 字段。

用法：
  python tools/migrate_uploads_to_sync_uploads.py

注意：脚本会打印将要迁移的条目并执行迁移。若希望先仅预览，请编辑脚本将 DO_MOVE=False。
"""
import sqlite3
from pathlib import Path
import shutil
import os

ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent
DATA_DIR = PROJECT_ROOT / 'data'
DB = ROOT / 'file_server.db'
# server_storage 已迁移到仓库的 data 目录下
OLD_UPLOAD_DIR = DATA_DIR / 'server_storage' / 'uploads'
NEW_SYNC_DIR = DATA_DIR / 'server_storage' / 'sync_uploads'

DO_MOVE = True

if not DB.exists():
    print('找不到数据库：', DB)
    raise SystemExit(1)

conn = sqlite3.connect(str(DB))
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# 查询所有在 uploads 下面的文件记录（无论 is_deleted）
# 兼容数据库中可能存储的相对路径（如 'data\\server_storage\\uploads\\...' 或 旧的 'server_storage\\uploads\\...'）或绝对路径
pattern_abs = str(OLD_UPLOAD_DIR) + '%'
# 同时兼容旧数据库中可能残留的相对路径格式
pattern_rel = 'data\\server_storage\\uploads\\%'
cur.execute("SELECT id, filename, filepath, uploader_id FROM files WHERE filepath LIKE ? OR filepath LIKE ?", (pattern_abs, pattern_rel))
rows = cur.fetchall()
if not rows:
    print('没有发现需要迁移的记录。')
    conn.close()
    raise SystemExit(0)

print(f'准备迁移 {len(rows)} 条记录：')
for r in rows:
    print('-', r['id'], r['filename'], '->', r['filepath'], 'uploader_id=', r['uploader_id'])

if not DO_MOVE:
    print('\nDO_MOVE=False，已退出（仅预览）')
    conn.close()
    raise SystemExit(0)

# 为每 uploader_id 查询 username
uids = sorted({r['uploader_id'] for r in rows})
user_map = {}
for uid in uids:
    cur2 = conn.execute('SELECT username FROM users WHERE id = ?', (uid,))
    rr = cur2.fetchone()
    if rr and rr['username']:
        user_map[uid] = rr['username']
    else:
        user_map[uid] = f'user_{uid}'

print('\n开始迁移：')
for r in rows:
    fid = r['id']
    raw_fp = r['filepath']
    filepath = Path(raw_fp)
    # 若数据库存的是相对路径（例如 'data/server_storage/uploads/...', 或旧的 'server_storage/uploads/...'），将其视为相对于项目根
    if not filepath.is_absolute():
        filepath = PROJECT_ROOT / raw_fp
    uid = r['uploader_id']
    username = user_map.get(uid, f'user_{uid}')
    if not filepath.exists():
        print(f'跳过 id={fid}，物理文件不存在: {filepath}')
        continue
    target_dir = NEW_SYNC_DIR / username
    target_dir.mkdir(parents=True, exist_ok=True)
    new_path = target_dir / filepath.name
    # 若目标已存在，改名为避免覆盖
    if new_path.exists():
        base = filepath.stem
        ext = filepath.suffix
        i = 1
        while True:
            cand = target_dir / f"{base}_{i}{ext}"
            if not cand.exists():
                new_path = cand
                break
            i += 1
    try:
        shutil.move(str(filepath), str(new_path))
        # 更新数据库
        conn.execute('UPDATE files SET filepath = ? WHERE id = ?', (str(new_path), fid))
        conn.commit()
        print(f'migrated id={fid} -> {new_path}')
    except Exception as e:
        print(f'迁移失败 id={fid}:', e)

print('\n迁移完成。建议重启 sync_adapter 或 Java 服务以确保路径变化被正确使用。')
conn.close()