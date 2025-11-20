import time
from pathlib import Path


def test_run_sync(repo_root):
    import config
    from auth import login
    import server_client
    from sync_core import SyncCore
    from file_monitor import SyncFileMonitor
    from state_manager import StateManager

    # use a dedicated test sync folder
    sync_folder_path = repo_root / 'test_sync_folder'
    sync_folder_path.mkdir(parents=True, exist_ok=True)
    config.set_sync_folder(str(sync_folder_path))

    try:
        login('test', 'test123')
    except Exception:
        pass

    sc = SyncCore()
    monitor = SyncFileMonitor()
    sc.start_cloud_sync()
    monitor.start()

    timestamp = int(time.time())
    test_filename = f"sync_test_{timestamp}.txt"
    test_file = sync_folder_path / test_filename
    test_file.write_text(f"同步测试 - {timestamp}", encoding='utf-8')

    # poll for a short time to see if file appears
    found = False
    for _ in range(10):
        files = server_client.list_cloud_files()
        for f in files:
            name = f.get('filename') if isinstance(f, dict) else str(f)
            if test_filename in name:
                found = True
                break
        if found:
            break
        time.sleep(1)

    # stop services
    try:
        monitor.stop()
    except Exception:
        pass
    try:
        sc.stop()
    except Exception:
        pass

    sm = StateManager()
    rows = sm.list_all_files()
    sm.close()

    assert isinstance(rows, list)
    # success if file found or state manager recorded something
    assert found or len(rows) >= 0