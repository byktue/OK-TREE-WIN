#!/usr/bin/env python
# -*- coding:utf-8 -*-
import sqlite3
import os
import logging
import threading
from pathlib import Path
from datetime import datetime
from config import get_config, SYNC_FOLDER

# 日志配置
logging.basicConfig(
    level=get_config("log", "level"),
    filename=get_config("log", "log_file"),
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding="utf-8"
)

# 本地元信息数据库路径
DB_FILE = Path(os.path.expanduser("~")) / ".netdisk_client" / "sync_state.db"
DB_FILE.parent.mkdir(exist_ok=True)

class StateManager:
    """同步状态管理器"""
    def __init__(self):
        # 允许在多个线程中使用同一个连接，但我们用线程锁保护并发访问
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        """初始化数据库表"""
        # 文件元信息表 & 同步日志表：在锁内执行以保证线程安全
        with self._lock:
            # 文件元信息表
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_state (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    relative_path TEXT UNIQUE NOT NULL,
                    md5 TEXT,
                    size INTEGER,
                    modify_time TEXT,
                    sync_status TEXT DEFAULT 'pending',
                    last_sync_time TEXT
                )
            ''')
            # 同步日志表
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS sync_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT,
                    create_time TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            self.conn.commit()

    def calculate_md5(self, file_path: Path) -> str:
        """计算文件MD5"""
        import hashlib
        md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
        return md5.hexdigest()

    def list_all_files(self) -> list:
        """返回所有已记录的本地文件同步状态列表"""
        self.cursor.execute('SELECT relative_path, md5, size, modify_time, sync_status, last_sync_time FROM file_state')
        rows = self.cursor.fetchall()
        result = []
        for row in rows:
            result.append({
                "relative_path": row[0],
                "md5": row[1],
                "size": row[2],
                "modify_time": row[3],
                "sync_status": row[4],
                "last_sync_time": row[5]
            })
        return result

    def update_file_state(self, local_file_path: Path):
        """更新本地文件元信息"""
        if not local_file_path.exists() or local_file_path.is_dir():
            return
        relative_path = str(local_file_path.relative_to(SYNC_FOLDER))
        md5 = self.calculate_md5(local_file_path)
        size = os.path.getsize(local_file_path)
        modify_time = datetime.fromtimestamp(os.path.getmtime(local_file_path)).isoformat()
        # 插入或更新
        with self._lock:
            self.cursor.execute('''
                INSERT OR REPLACE INTO file_state 
                (relative_path, md5, size, modify_time, sync_status, last_sync_time)
                VALUES (?, ?, ?, ?, 'success', ?)
            ''', (relative_path, md5, size, modify_time, datetime.now().isoformat()))
            self.conn.commit()

    def get_file_state(self, relative_path: str) -> dict:
        """获取文件同步状态"""
        with self._lock:
            self.cursor.execute('SELECT * FROM file_state WHERE relative_path = ?', (relative_path,))
            row = self.cursor.fetchone()
        if not row:
            return {}
        return {
            "id": row[0],
            "relative_path": row[1],
            "md5": row[2],
            "size": row[3],
            "modify_time": row[4],
            "sync_status": row[5],
            "last_sync_time": row[6]
        }

    def add_sync_log(self, event_type: str, file_path: str, status: str, message: str = ""):
        """添加同步日志"""
        with self._lock:
            self.cursor.execute('''
                INSERT INTO sync_log (event_type, file_path, status, message)
                VALUES (?, ?, ?, ?)
            ''', (event_type, file_path, status, message))
            self.conn.commit()
        # 同时写入日志文件
        if status == "success":
            logging.info(f"{event_type} - {file_path} - {message}")
        else:
            logging.error(f"{event_type} - {file_path} - {message}")

    def close(self):
        """关闭数据库连接"""
        try:
            with self._lock:
                self.conn.close()
        except Exception:
            try:
                self.conn.close()
            except Exception:
                pass

    def list_all_files(self) -> list:
        """返回所有已记录的本地文件同步状态列表"""
        with self._lock:
            self.cursor.execute('SELECT relative_path, md5, size, modify_time, sync_status, last_sync_time FROM file_state')
            rows = self.cursor.fetchall()
        result = []
        for row in rows:
            result.append({
                "relative_path": row[0],
                "md5": row[1],
                "size": row[2],
                "modify_time": row[3],
                "sync_status": row[4],
                "last_sync_time": row[5]
            })
        return result