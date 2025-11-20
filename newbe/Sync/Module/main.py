#!/usr/bin/env python
# -*- coding:utf-8 -*-
import signal
import sys
import time
import config
from auth import login, get_token, decrypt_data
from file_monitor import SyncFileMonitor
from sync_core import SyncCore
from state_manager import StateManager

# 全局模块实例
monitor = None
sync_core = None

def graceful_exit(signum=None, frame=None):
    """优雅退出"""
    print("\n客户端正在退出...")
    try:
        if monitor and getattr(monitor, 'is_running', False):
            monitor.stop()
    except Exception:
        pass
    try:
        if sync_core:
            sync_core.stop()
    except Exception:
        pass
    try:
        StateManager().close()
    except Exception:
        pass
    sys.exit(0)

def user_login():
    """用户登录流程：优先使用已保存的 Token"""
    token = get_token()
    if token:
        username = decrypt_data(config.get_config("auth", "username"))
        print(f"已自动登录：{username}")
        return True
    # 手动登录
    print("请输入网盘账号信息：")
    username = input("用户名：")
    password = input("密码：")
    token = login(username, password)
    if token:
        print("登录成功！")
        return True
    else:
        print("登录失败，请重试！")
        return False

def start_sync():
    """启动/启动并返回 sync_core 与 monitor 实例"""
    global sync_core, monitor
    sync_core = SyncCore()
    monitor = SyncFileMonitor()
    sync_core.start_cloud_sync()
    monitor.start()
    return sync_core, monitor

def stop_sync():
    global sync_core, monitor
    if monitor and getattr(monitor, 'is_running', False):
        monitor.stop()
    if sync_core:
        sync_core.stop()

def restart_sync():
    stop_sync()
    return start_sync()

def choose_sync_folder():
    """交互式选择/设置本地同步目录（会立即生效）"""
    print(f"当前同步目录：{config.SYNC_FOLDER}")
    new_path = input("请输入新的同步目录路径（回车取消）：").strip()
    if not new_path:
        print("取消修改。")
        return
    try:
        config.set_sync_folder(new_path)
        print(f"已更新本地同步目录为：{config.SYNC_FOLDER}")
        # 重新启动 monitor 以生效新的目录
        restart_sync()
    except Exception as e:
        print(f"设置同步目录失败：{e}")

def show_status():
    """显示同步状态（同步中/同步完成/连接断开）"""
    conn_status = sync_core.get_connection_status() if sync_core else 'unknown'
    monitor_status = 'running' if monitor and getattr(monitor, 'is_running', False) else 'stopped'
    # 简单判断是否有挂起任务：查看数据库最近同步时间
    sm = StateManager()
    files = sm.list_all_files()
    last_sync = None
    for f in files:
        if f.get('last_sync_time'):
            if not last_sync or f['last_sync_time'] > last_sync:
                last_sync = f['last_sync_time']
    sm.close()
    print("--- 同步状态 ---")
    print(f"服务器连接：{conn_status}")
    print(f"本地监控：{monitor_status}")
    print(f"最近同步时间：{last_sync if last_sync else '暂无同步记录'}")

def show_synced_files(limit: int = 50):
    """展示已记录的同步文件及状态"""
    sm = StateManager()
    files = sm.list_all_files()
    if not files:
        print("没有已记录的同步文件。")
        sm.close()
        return
    print(f"已记录文件（最多显示 {limit} 项）：")
    for i, f in enumerate(files[:limit], 1):
        print(f"{i}. {f['relative_path']} | 状态: {f['sync_status']} | 大小: {f['size']} | 最后同步: {f['last_sync_time']}")
    sm.close()

def main():
    # 注册退出信号
    signal.signal(signal.SIGINT, graceful_exit)
    try:
        signal.signal(signal.SIGTERM, graceful_exit)
    except Exception:
        pass

    # 登录验证
    if not user_login():
        sys.exit(1)

    # 启动同步
    start_sync()

    # 交互式菜单
    try:
        while True:
            print('\n--- 主菜单 ---')
            print('1) 显示同步状态')
            print('2) 选择/更改本地同步目录')
            print('3) 重启同步')
            print('4) 显示同步文件列表')
            print('5) 退出')
            choice = input('请选择操作（数字）：').strip()
            if choice == '1':
                show_status()
            elif choice == '2':
                choose_sync_folder()
            elif choice == '3':
                restart_sync()
                print('已重启同步。')
            elif choice == '4':
                show_synced_files()
            elif choice == '5':
                graceful_exit()
            else:
                print('无效选项，请重试。')
            time.sleep(0.1)
    except KeyboardInterrupt:
        graceful_exit()


if __name__ == "__main__":
    main()