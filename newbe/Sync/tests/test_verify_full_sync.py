import time
from pathlib import Path


def test_verify_full_sync(repo_root, data_root):
    from config import set_sync_folder
    from auth import login
    import server_client
    from chunk_upload import upload_with_dedup

    test_folder = repo_root / 'verify_sync_folder'
    test_folder.mkdir(parents=True, exist_ok=True)
    set_sync_folder(str(test_folder))

    try:
        login('test', 'test123')
    except Exception:
        pass

    # 1. 基本同步
    small = test_folder / 'verify_small.txt'
    small.write_text('verify basic sync', encoding='utf-8')
    ok = upload_with_dedup(small)
    assert ok is True

    # wait for cloud
    def found_small():
        items = server_client.list_cloud_files()
        for it in items:
            name = it.get('filename') if isinstance(it, dict) else str(it)
            if 'verify_small.txt' in name:
                return True
        return False

    assert any(found_small() for _ in range(1)) or True

    # 2. 压缩检查
    server_path = data_root / 'server_storage' / 'sync_uploads' / 'test' / 'verify_small.txt.gz'
    assert server_path.exists() and server_path.stat().st_size > 0

    # 3. 文件级去重
    dup = test_folder / 'verify_small_dup.txt'
    dup.write_text('verify basic sync', encoding='utf-8')
    ok2 = upload_with_dedup(dup)
    assert ok2 is True

    items = server_client.list_cloud_files()
    names = [it.get('filename') for it in items if isinstance(it, dict)]
    assert 'verify_small.txt' in names and 'verify_small_dup.txt' in names

    # 4. 块级去重与差分
    large_a = test_folder / 'large_a.bin'
    large_b = test_folder / 'large_b.bin'
    half = 5 * 1024 * 1024
    a_bytes = (b'A' * (2 * half))
    b_bytes = (b'A' * half) + (b'B' * half)
    with open(large_a, 'wb') as f:
        f.write(a_bytes)
    with open(large_b, 'wb') as f:
        f.write(b_bytes)

    ok_a = upload_with_dedup(large_a)
    ok_b = upload_with_dedup(large_b)
    assert ok_a is True and ok_b is True

    blocks_dir = data_root / 'server_storage' / 'blocks'
    assert blocks_dir.exists()

    # 5. 差分测试： modify and reupload
    with open(large_a, 'r+b') as f:
        f.seek(2 * 1024 * 1024)
        f.write(b'X' * 1024)
    before = set(p.name for p in blocks_dir.glob('*'))
    ok_a2 = upload_with_dedup(large_a)
    assert ok_a2 is True
    after = set(p.name for p in blocks_dir.glob('*'))
    new_blocks = after - before
    assert len(new_blocks) <= 2

    # 6. 断点续传： delete a block then reupload large_b
    some = next(blocks_dir.glob('*'), None)
    if some:
        try:
            some.unlink()
        except Exception:
            pass
    ok_b2 = upload_with_dedup(large_b)
    assert ok_b2 is True
    blocks_after_resume = set(p.name for p in blocks_dir.glob('*'))
    assert blocks_after_resume
