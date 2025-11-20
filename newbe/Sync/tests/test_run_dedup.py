import time
from pathlib import Path


def prepare_module_path():
    # conftest ensures Module is on sys.path
    pass


def test_run_dedup(repo_root, data_root):
    prepare_module_path()
    import config
    from auth import login
    import server_client
    from chunk_upload import upload_with_dedup

    sync_folder = repo_root / 'test_sync_folder'
    sync_folder.mkdir(parents=True, exist_ok=True)
    config.set_sync_folder(str(sync_folder))

    # attempt login (may be optional)
    try:
        login('test', 'test123')
    except Exception:
        pass

    # small file uploads
    small1 = sync_folder / 'small1.txt'
    small1.write_text('hello dedup test', encoding='utf-8')
    ok1 = upload_with_dedup(small1)
    assert ok1 is True

    small_dup = sync_folder / 'small1_dup.txt'
    small_dup.write_text('hello dedup test', encoding='utf-8')
    ok_dup = upload_with_dedup(small_dup)
    assert ok_dup is True

    # big files for block dedup
    large_a = sync_folder / 'large_a.bin'
    large_b = sync_folder / 'large_b.bin'
    half = 5 * 1024 * 1024
    a_bytes = (b'A' * (2 * half))
    b_bytes = (b'A' * half) + (b'B' * half)
    with open(large_a, 'wb') as f:
        f.write(a_bytes)
    with open(large_b, 'wb') as f:
        f.write(b_bytes)

    ok_a = upload_with_dedup(large_a)
    ok_b = upload_with_dedup(large_b)
    assert ok_a is True
    assert ok_b is True

    # wait a short moment for adapter to write blocks
    time.sleep(1)

    blocks_dir = data_root / 'server_storage' / 'blocks'
    # blocks directory should exist (adapter may keep it empty if blockless flow used)
    assert blocks_dir.exists()
    # also ensure cloud files list is returned
    files = server_client.list_cloud_files()
    assert isinstance(files, list)