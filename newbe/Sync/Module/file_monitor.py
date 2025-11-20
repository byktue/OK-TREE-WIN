#!/usr/bin/env python
# -*- coding:utf-8 -*-
from watchdog.observers import Observer
from watchdog.events import RegexMatchingEventHandler
from pathlib import Path
from config import SYNC_FOLDER, SKIP_SUFFIXES, RECURSIVE_MONITOR
from server_client import upload_file, delete_file
import re

# 生成忽略文件的正则表达式
IGNORE_PATTERNS = [re.compile(f".*{suffix}$") for suffix in SKIP_SUFFIXES]

class SyncFileHandler(RegexMatchingEventHandler):
    """同步文件夹事件处理器

    注意：不要在初始化时固定 `SYNC_FOLDER` 的值，因为测试可能在运行时修改配置。
    在监控器启动时会将当前 `SYNC_FOLDER` 赋值到 `handler.sync_folder`。
    """
    def __init__(self):
        super().__init__()
        self.sync_folder = None

    def on_created(self, event):
        """文件创建事件"""
        self._handle_event(event.src_path, "create")

    def on_modified(self, event):
        """文件修改事件"""
        self._handle_event(event.src_path, "modify")

    def on_deleted(self, event):
        """文件删除事件"""
        self._handle_event(event.src_path, "delete")

    def on_moved(self, event):
        """文件移动/重命名事件"""
        self._handle_event(event.src_path, "delete")
        self._handle_event(event.dest_path, "create")

    def _is_ignored(self, path: str) -> bool:
        """判断文件是否需要忽略"""
        if Path(path).is_dir():
            return False
        filename = Path(path).name
        return any(pattern.match(filename) for pattern in IGNORE_PATTERNS)

    def _handle_event(self, file_path: str, event_type: str):
        """处理文件事件"""
        if self._is_ignored(file_path):
            return
        path = Path(file_path)
        if event_type in ["create", "modify"]:
            upload_file(path)
        elif event_type == "delete":
            # 使用当前 handler.sync_folder（若未设置则使用全局 SYNC_FOLDER）
            base = Path(self.sync_folder) if self.sync_folder else Path(SYNC_FOLDER)
            try:
                relative_path = path.relative_to(base)
            except Exception:
                # 如果无法相对化，退回到文件名
                relative_path = path.name
            delete_file(str(relative_path))

class SyncFileMonitor:
    """文件监控器"""
    def __init__(self):
        self.observer = Observer()
        self.handler = SyncFileHandler()
        self.is_running = False

    def start(self):
        """启动监控

        在启动时将当前 `SYNC_FOLDER` 的值赋给 handler，以避免在 handler 初始化后配置更改导致的不一致。
        """
        # 更新 handler 的 sync_folder 到当前配置值
        try:
            self.handler.sync_folder = SYNC_FOLDER
        except Exception:
            self.handler.sync_folder = None
        self.observer.schedule(self.handler, str(SYNC_FOLDER), recursive=RECURSIVE_MONITOR)
        self.observer.start()
        self.is_running = True
        print(f"文件监控已启动，监控目录：{SYNC_FOLDER}")

    def stop(self):
        """停止监控"""
        self.observer.stop()
        self.observer.join()
        self.is_running = False
        print("文件监控已停止")