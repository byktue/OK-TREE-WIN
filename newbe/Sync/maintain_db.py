git rm -r --cached .
#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
维护脚本：每 5 秒检查 `file_server.db` 中的文件记录与磁盘实际文件是否一致。
- 若某条记录对应的物理文件在磁盘中不存在，则删除该 DB 记录（files 表）。
- 支持绝对路径与相对路径（会在仓库根、`data/server_storage/sync_uploads`、`data/server_storage/uploads` 下尝试查找）。

用法：在项目根运行 `python maintain_db.py`，或者在服务端启动时并行运行此脚本。
"""
import sqlite3
import time
import logging
import os
from pathlib import Path
from typing import List

# 配置
BASE_DIR = Path(__file__).parent.resolve()
# newbe 目录才是项目根，Sync 在其下
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = BASE_DIR / "file_server.db"
# 优先检查的存储根目录（按优先级）
# server_storage 现在位于仓库的 data 目录下
STORAGE_ROOTS = [DATA_DIR / "server_storage" / "sync_uploads", DATA_DIR / "server_storage" / "uploads"]
# 检查间隔（秒）
DEFAULT_INTERVAL = 5

# 日志配置
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("maintain_db")


def _candidates_for_path(db_filepath: str, storage_roots: List[Path]) -> List[Path]:
    """根据 DB 中的 filepath 字符串生成可能的磁盘路径候选列表。"""
    candidates: List[Path] = []
    fp = db_filepath or ""
    fp = fp.replace('\\\r', '').replace('\\\n', '').strip()
    # 直接尝试原始字符串（可能是绝对路径）
    try:
        raw = Path(fp)
        if raw.is_absolute():
            candidates.append(raw)
    except Exception:
        pass

    # 尝试相对于仓库根
    try:
        candidates.append((BASE_DIR / fp).resolve())
    except Exception:
        pass
    try:
        candidates.append((PROJECT_ROOT / fp).resolve())
    except Exception:
        pass
    try:
        candidates.append((DATA_DIR / fp).resolve())
    except Exception:
        pass

    # 尝试每个 storage root 下
    for root in storage_roots:
        try:
            candidates.append((root / fp).resolve())
        except Exception:
            pass

    # 规范化并去重
    seen = set()
    uniq = []
    for p in candidates:
        s = str(p)
        if s not in seen:
            seen.add(s)
            uniq.append(p)
    return uniq


def file_exists_in_any(fp: str, storage_roots: List[Path]) -> bool:
    """判断 DB 中的 filepath 在磁盘上是否存在（考虑多个候选位置）。"""
    for cand in _candidates_for_path(fp, storage_roots):
        try:
            if cand.exists():
                return True
        except Exception:
            # 忽略无法访问的候选路径
            continue
    return False


def monitor_and_clean_db(db_path: Path = DB_PATH, storage_roots: List[Path] = STORAGE_ROOTS, interval: int = DEFAULT_INTERVAL):
    """主循环：每 interval 秒检查一次数据库并删除不存在的文件记录。

    该函数会持续运行直到收到 KeyboardInterrupt。
    """
    logger.info(f"开始监控 DB：{db_path}（每 {interval} 秒）")

    if not db_path.exists():
        logger.error(f"数据库文件不存在：{db_path}")
        return

    try:
        while True:
            try:
                # 使用独立连接，降低锁冲突概率；设较大 timeout
                conn = sqlite3.connect(str(db_path), timeout=10)
                conn.execute('PRAGMA journal_mode=WAL;')
                cur = conn.cursor()

                # 确认 files 表存在
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='files'")
                if not cur.fetchone():
                    logger.warning("数据库中未找到 `files` 表，跳过此次检查")
                    conn.close()
                    time.sleep(interval)
                    continue

                cur.execute("SELECT id, filepath FROM files")
                rows = cur.fetchall()
                removed = 0
                for row in rows:
                    row_id, filepath = row[0], row[1]
                    if not filepath:
                        # 如果 filepath 为空，直接删除记录
                        logger.info(f"删除空 filepath 记录 id={row_id}")
                        cur.execute("DELETE FROM files WHERE id=?", (row_id,))
                        removed += 1
                        continue

                    exists = file_exists_in_any(filepath, storage_roots)
                    if not exists:
                        logger.info(f"文件缺失，删除 DB 记录 id={row_id} filepath={filepath}")
                        cur.execute("DELETE FROM files WHERE id=?", (row_id,))
                        removed += 1

                if removed > 0:
                    conn.commit()
                    logger.info(f"本次扫描移除 {removed} 条失效记录")
                else:
                    # 减少磁盘日志噪音
                    logger.debug("本次扫描未发现失效记录")

            except Exception as e:
                logger.exception(f"检查/清理过程中发生异常：{e}")
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("检测到中断信号，停止监控并退出")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='监控并清理 file_server.db 中已不存在的文件记录')
    parser.add_argument('--db', '-d', help='file_server.db 路径（默认为仓库根下的 file_server.db）', default=str(DB_PATH))
    parser.add_argument('--interval', '-i', help='扫描间隔（秒）', type=int, default=DEFAULT_INTERVAL)
    parser.add_argument('--roots', '-r', help='以分号分隔的 storage 根目录（相对于仓库根或绝对路径）', default=None)
    args = parser.parse_args()

    dbp = Path(args.db)
    if args.roots:
        roots = []
        for r in args.roots.split(';'):
            path = Path(r)
            if path.is_absolute():
                roots.append(path)
            else:
                roots.append((PROJECT_ROOT / r).resolve())
    else:
        roots = STORAGE_ROOTS

    monitor_and_clean_db(db_path=dbp, storage_roots=roots, interval=args.interval)
