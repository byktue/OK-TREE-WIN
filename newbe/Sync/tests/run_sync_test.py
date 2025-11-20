#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
同步测试脚本

用途：把客户端的本地同步文件夹设置为指定路径（例如：
`C:\Users\26930\Desktop\先进集体材料`），启动客户端的 `SyncCore` 与 `SyncFileMonitor`，
创建一个测试文件并等待若干秒观察是否被上传到云端（通过 `server_client.list_cloud_files()` 验证）。

注意：
- 运行前请确保已安装依赖（在 PowerShell 中运行：
  `python -m pip install --user requests watchdog cryptography`）
- 若你要测试对接 `sync_adapter.py`，请先启动它并确保 `Module/config.py` 的 `BASE_URL` 指向 `http://localhost:4000`。

如何运行：
  在工作区根目录运行：
    python tests/run_sync_test.py

脚本不会自动删除你本地现有文件，请谨慎使用。
"""
import sys
import time
from pathlib import Path


def prepare_module_path():
    # 将 Module 目录加入 sys.path，便于导入项目模块
    repo_root = Path(__file__).resolve().parent.parent
    module_path = repo_root / 'Module'
    if str(module_path) not in sys.path:
        sys.path.insert(0, str(module_path))


def run_test(sync_folder: str, wait_seconds: int = 30):
    prepare_module_path()
    import config

    sync_folder_path = Path(sync_folder)
    if not sync_folder_path.exists():
        print(f"同步目录不存在，正在创建：{sync_folder_path}")
        sync_folder_path.mkdir(parents=True, exist_ok=True)

    print(f"设置客户端同步目录为：{sync_folder_path}")
    # 更新 config 中的同步目录（会更新 config.ini）
    try:
        config.set_sync_folder(str(sync_folder_path))
    except Exception as e:
        print("设置同步目录失败：", e)

    # 尝试登录以获取 Token（基于服务端的 /api/auth/login）
    try:
        from auth import login
        print('尝试登录服务器以获取 Token（默认 test/test123）...')
        token = login('test', 'test123')
        if token:
            print('登录成功，已获取并保存 token（将用于后续上传请求）')
        else:
            print('登录未成功或未返回 token；若使用 adapter（4000）请确保其支持登录或直接使用 adapter 不需要 token')
    except Exception as e:
        print('尝试登录时出错（忽略）：', e)

    # 现在再导入依赖于 config.SYNC_FOLDER 的模块，确保它们读取到新的配置
    import server_client
    from sync_core import SyncCore
    from file_monitor import SyncFileMonitor
    from state_manager import StateManager

    # 启动 SyncCore 与文件监控
    sc = SyncCore()
    monitor = SyncFileMonitor()
    print("启动云端拉取线程与本地监控...")
    sc.start_cloud_sync()
    monitor.start()

    # 创建测试文件
    timestamp = int(time.time())
    test_filename = f"sync_test_{timestamp}.txt"
    test_file = sync_folder_path / test_filename
    print(f"创建测试文件：{test_file}")
    test_file.write_text(f"同步测试 - {timestamp}", encoding='utf-8')


    print(f"开始轮询云端（超时 {wait_seconds} 秒）以便检测文件是否已同步，间隔 2 秒...")
    found = False
    elapsed = 0
    poll_interval = 2
    while elapsed < wait_seconds:
        try:
            files = server_client.list_cloud_files()
        except Exception as e:
            print(f'服务连通或请求失败（{e}），将在 {poll_interval} 秒后重试')
            files = []
        # 打印返回样例便于调试（最多前10项）
        try:
            if files:
                print('云端返回（样例最多10项）：')
                for item in files[:10]:
                    print('  -', item)
        except Exception:
            pass

        for f in files:
            name = ''
            rel = ''
            if isinstance(f, dict):
                name = f.get('filename') or f.get('relativePath') or ''
                rel = f.get('relativePath', '')
            elif isinstance(f, str):
                name = f
                rel = f
            else:
                try:
                    name = f.get('filename') or f.get('relativePath') or ''
                    rel = f.get('relativePath', '')
                except Exception:
                    s = str(f)
                    name = s
                    rel = s

            if test_filename == name or test_filename in name or test_filename in rel:
                found = True
                print('在云端找到测试文件，记录：', f)
                break
        if found:
            break
        time.sleep(poll_interval)
        elapsed += poll_interval
        print('.', end='', flush=True)
    print('\n轮询结束')

    if not found:
        print('未能在云端找到测试文件。请检查服务端（Java 服务或 sync_adapter）是否已启动，或检查 Module/config.py 中的 BASE_URL 配置是否正确。')

    # 停止监控与同步
    try:
        monitor.stop()
    except Exception:
        pass
    try:
        sc.stop()
    except Exception:
        pass

    # 打印本地状态数据库中最近几条记录（方便诊断）
    try:
        sm = StateManager()
        rows = sm.list_all_files()
        print(f"本地状态库记录数：{len(rows)}，前10条：")
        for r in rows[:10]:
            print(r)
        sm.close()
    except Exception as e:
        print('读取本地状态库失败：', e)

    print('测试完成。')
    return found


if __name__ == '__main__':
    # 将下面路径替换为你要求的路径
    target_path = r"C:\Users\26930\Desktop\先进集体材料"
    result = run_test(target_path, wait_seconds=30)
    print('结果：', '已同步' if result else '未同步')
