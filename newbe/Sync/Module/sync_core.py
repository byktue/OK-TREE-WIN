#!/usr/bin/env python
# -*- coding:utf-8 -*-
import time
import threading
from config import PULL_INTERVAL, SYNC_FOLDER, SKIP_SUFFIXES
from server_client import list_cloud_files, download_file, upload_file
from state_manager import StateManager
from pathlib import Path
from server_client import check_server

class SyncCore:
    """双向同步核心"""
    def __init__(self):
        self.state_manager = StateManager()
        self.is_running = True
        # 连接状态：'connected' / 'disconnected' / 'unknown'
        self.connection_status = 'unknown'
        self._conn_thread = None

    def sync_local_to_cloud(self, local_file_path: Path, event_type: str):
        """本地→云端同步"""
        try:
            if event_type in ["create", "modify"]:
                from server_client import upload_file
                success = upload_file(local_file_path)
                if success:
                    self.state_manager.update_file_state(local_file_path)
                    self.state_manager.add_sync_log(event_type, str(local_file_path), "success")
                else:
                    self.state_manager.add_sync_log(event_type, str(local_file_path), "failed", "上传失败")
            elif event_type == "delete":
                from server_client import delete_file
                relative_path = str(local_file_path.relative_to(SYNC_FOLDER))
                success = delete_file(relative_path)
                if success:
                    self.state_manager.add_sync_log(event_type, str(local_file_path), "success")
                else:
                    self.state_manager.add_sync_log(event_type, str(local_file_path), "failed", "删除失败")
        except Exception as e:
            self.state_manager.add_sync_log(event_type, str(local_file_path), "error", str(e))

    def sync_cloud_to_local(self):
        """云端→本地同步（定时拉取）"""
        while self.is_running:
            try:
                cloud_files = list_cloud_files()
            # 如果无法从服务端获取列表，list_cloud_files 会返回 [] 并打印错误，
            # 连接状态由连接监测线程维护
                for cloud_file in cloud_files:
                    # 支持服务端返回字符串或字典
                    if isinstance(cloud_file, dict):
                        cloud_relative_path = cloud_file.get("relativePath", cloud_file.get("filename"))
                        cloud_md5 = cloud_file.get("md5")
                    else:
                        cloud_relative_path = str(cloud_file)
                        cloud_md5 = None

                    local_file_path = SYNC_FOLDER / cloud_relative_path
                    # 本地文件不存在或MD5不一致则下载
                    if not local_file_path.exists():
                        # download_file 接受 dict 或 identifier；若为字符串则构造最小信息
                        download_file(cloud_file if isinstance(cloud_file, dict) else {"relativePath": cloud_relative_path})
                        self.state_manager.update_file_state(local_file_path)
                        self.state_manager.add_sync_log("download", str(local_file_path), "success")
                    else:
                        # 若服务端未提供 md5，则跳过 md5 对比，仅在不存在时下载；若提供，则比较并更新
                        if cloud_md5:
                            local_md5 = self.state_manager.calculate_md5(local_file_path)
                            if local_md5 != cloud_md5:
                                download_file(cloud_file)
                                self.state_manager.update_file_state(local_file_path)
                                self.state_manager.add_sync_log("update", str(local_file_path), "success")
                time.sleep(PULL_INTERVAL)
            except Exception as e:
                # 记录异常；StateManager 已实现线程锁，但这里仍保护记录操作
                try:
                    self.state_manager.add_sync_log("pull", "cloud", "error", str(e))
                except Exception:
                    print("记录同步异常失败：", e)
                time.sleep(PULL_INTERVAL)

    def full_sync_once(self):
        """一次性的全量双向同步：先本地->云端（上传新增/变更），再云端->本地（下载新增/变更）。"""
        try:
            from auth import get_username
            cur_user = get_username()
        except Exception:
            cur_user = ''

        # 获取云端列表（server_client 已尽可能返回当前用户的条目）
        cloud_files = list_cloud_files()
        cloud_map = {}
        for cf in cloud_files:
            if isinstance(cf, dict):
                rel = cf.get('relativePath') or cf.get('filename')
                if rel:
                    cloud_map[str(rel)] = cf

        # 本地 -> 云：遍历本地文件，上传缺失或 md5 不同的文件
        for p in SYNC_FOLDER.rglob('*'):
            if p.is_dir():
                continue
            if any(str(p).endswith(s) for s in SKIP_SUFFIXES):
                continue
            try:
                rel = str(p.relative_to(SYNC_FOLDER))
            except Exception:
                continue
            local_md5 = self.state_manager.calculate_md5(p)
            cf = cloud_map.get(rel)
            need_upload = False
            if not cf:
                need_upload = True
            else:
                cloud_md5 = cf.get('md5')
                if cloud_md5 and cloud_md5 != local_md5:
                    need_upload = True

            if need_upload:
                try:
                    ok = upload_file(p)
                    if ok:
                        self.state_manager.update_file_state(p)
                        self.state_manager.add_sync_log('upload', str(p), 'success')
                    else:
                        self.state_manager.add_sync_log('upload', str(p), 'failed')
                except Exception as e:
                    self.state_manager.add_sync_log('upload', str(p), 'error', str(e))
                # avoid spamming
                time.sleep(0.1)

        # 刷新云端列表
        cloud_files = list_cloud_files()

        # 云端 -> 本地：下载本地缺失或 md5 不同的文件
        for cf in cloud_files:
            if not isinstance(cf, dict):
                continue
            rel = cf.get('relativePath') or cf.get('filename')
            if not rel:
                continue
            local_path = SYNC_FOLDER / rel
            cloud_md5 = cf.get('md5')
            if not local_path.exists():
                try:
                    download_file(cf)
                    self.state_manager.update_file_state(local_path)
                    self.state_manager.add_sync_log('download', str(local_path), 'success')
                except Exception as e:
                    self.state_manager.add_sync_log('download', str(local_path), 'error', str(e))
            else:
                if cloud_md5:
                    try:
                        local_md5 = self.state_manager.calculate_md5(local_path)
                        if local_md5 != cloud_md5:
                            download_file(cf)
                            self.state_manager.update_file_state(local_path)
                            self.state_manager.add_sync_log('update', str(local_path), 'success')
                    except Exception as e:
                        self.state_manager.add_sync_log('compare', str(local_path), 'error', str(e))
        # 全量同步完成
        print('一次性全量同步完成（本地->云, 云->本地）')

    def start_cloud_sync(self):
        """启动云端→本地同步线程"""
        # 先执行一次性的全量双向同步（本地->云，再云->本地），确保初始一致性
        try:
            self.full_sync_once()
        except Exception as e:
            print('全量同步执行失败：', e)

        # 启动云端拉取线程（持续增量拉取）
        t = threading.Thread(target=self.sync_cloud_to_local, daemon=True)
        t.start()
        # 启动连接监测线程
        self._conn_thread = threading.Thread(target=self._connection_monitor, daemon=True)
        self._conn_thread.start()
        print(f"云端拉取同步已启动，间隔：{PULL_INTERVAL}秒；连接监测已启动")

    def _connection_monitor(self, interval: int = 10):
        """周期性检测服务端连通性并更新状态"""
        while self.is_running:
            try:
                ok = check_server()
                self.connection_status = 'connected' if ok else 'disconnected'
            except Exception:
                self.connection_status = 'disconnected'
            time.sleep(interval)

    def get_connection_status(self) -> str:
        """返回当前连接状态字符串"""
        return self.connection_status

    def stop(self):
        """停止同步"""
        self.is_running = False
        self.state_manager.close()
        print("同步核心已停止")