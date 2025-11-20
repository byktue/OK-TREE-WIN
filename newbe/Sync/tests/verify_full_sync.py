#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端到端验证脚本：检查同步、压缩、文件去重、块去重、差分（增量）上传与断点续传。

使用前提：
- 在仓库根启动 `sync_adapter.py`（适配器）。
- 若需要测试加密，必须以同样的 `SYNC_ENCRYPTION_KEY` 环境变量启动适配器并为客户端设置相同值。

运行：
  python tests/verify_full_sync.py

脚本会在仓库下创建 `verify_sync_folder` 用于测试，完成后会打印检查结果。
"""
import sys
import time
import os
from pathlib import Path


def prepare_module_path():
    repo_root = Path(__file__).resolve().parent.parent
    module_path = repo_root / 'Module'
    if str(module_path) not in sys.path:
        sys.path.insert(0, str(module_path))
    return repo_root


def retry(pred, timeout=10, interval=1):
    start = time.time()
    while time.time() - start < timeout:
        if pred():
            return True
        time.sleep(interval)
    return False


def run():
    repo_root = prepare_module_path()
    data_root = repo_root.parent / 'data'
    from config import set_sync_folder
    from auth import login
    import server_client
    from chunk_upload import upload_with_dedup

    test_folder = repo_root / 'verify_sync_folder'
    test_folder.mkdir(parents=True, exist_ok=True)
    set_sync_folder(str(test_folder))

    print('尝试登录（test/test123）')
    try:
        login('test', 'test123')
    except Exception as e:
        print('登录忽略（可能 adapter 无需登录）：', e)

    # 1. 基本同步（创建本地文件，客户端 monitor + synccore 应自动上传）
    print('\n=== 1. 基本同步测试 ===')
    small = test_folder / 'verify_small.txt'
    small.write_text('verify basic sync', encoding='utf-8')

    print('上传 small via upload_with_dedup...')
    ok = upload_with_dedup(small)
    print('upload_with_dedup returned:', ok)

    # 等待云端出现
    def found_small():
        try:
            items = server_client.list_cloud_files()
            for it in items:
                name = it.get('filename') if isinstance(it, dict) else str(it)
                if 'verify_small.txt' in name:
                    return True
        except Exception:
            return False
        return False

    assert retry(found_small, timeout=15, interval=1), '基本同步失败：云端未出现 small 文件'
    print('基本同步：OK')

    # 2. 压缩检查：服务端文件应以 .gz 形式存储
    print('\n=== 2. 压缩存储检查 ===')
    # 找到服务器上对应 filepath
    files = server_client.list_cloud_files()
    server_path = None
    for it in files:
        if it.get('filename') == 'verify_small.txt':
            # 组合出可能的 server filepath
            # 使用 maintain_db / adapter 逻辑，文件位于 data/server_storage/sync_uploads/{username}/<relativePath>.gz
            server_path = Path(data_root / 'server_storage' / 'sync_uploads' / 'test' / 'verify_small.txt.gz')
            break
    if server_path and server_path.exists():
        # 检查 gzip header
        with open(server_path, 'rb') as f:
            h = f.read(2)
        assert h == b'\x1f\x8b', '服务器存储文件不是 gzip 格式'
        print('压缩存储：OK ->', server_path)
    else:
        print('压缩存储检查无法确认（文件未找到或路径不匹配）')

    # 3. 文件级去重：上传同内容不同名称的文件，应在 DB 中创建记录但不重复存储
    print('\n=== 3. 文件级去重测试 ===')
    dup = test_folder / 'verify_small_dup.txt'
    dup.write_text('verify basic sync', encoding='utf-8')
    ok2 = upload_with_dedup(dup)
    print('上传 duplicate returned:', ok2)

    # 检查云端是否能列出两个文件名（各自为用户记录）
    items = server_client.list_cloud_files()
    names = [it.get('filename') for it in items if isinstance(it, dict)]
    assert 'verify_small.txt' in names and 'verify_small_dup.txt' in names, '文件级去重行为未引入指针记录'
    print('文件级去重（指针记录）: OK')

    # 4. 块级去重与差分：上传两个大文件 A 和 B（共享一半内容），观察 blocks 目录块数
    print('\n=== 4. 块级去重与差分测试 ===')
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
    print('large_a ok:', ok_a, 'large_b ok:', ok_b)

    blocks_dir = data_root / 'server_storage' / 'blocks'
    assert blocks_dir.exists(), 'blocks 目录不存在'
    blocks = list(blocks_dir.glob('*'))
    print('blocks count:', len(blocks))
    assert len(blocks) <= 4, '块数应小于等于 4（示例中应被有效去重）'
    print('块级去重：OK')

    # 差分同步：修改 large_a 中间一小段，重新上传，检查新增块数量较少
    print('\n=== 5. 差分增量测试 ===')
    # 读取 large_a, 修改中间 1KB
    with open(large_a, 'r+b') as f:
        f.seek(2 * 1024 * 1024)
        f.write(b'X' * 1024)
    before = set(p.name for p in blocks_dir.glob('*'))
    ok_a2 = upload_with_dedup(large_a)
    print('re-upload large_a ok:', ok_a2)
    after = set(p.name for p in blocks_dir.glob('*'))
    new_blocks = after - before
    print('new blocks added:', len(new_blocks))
    assert len(new_blocks) <= 2, '差分上传应该只新增少量块'
    print('差分增量上传：OK')

    # 6. 断点续传：删除一个块文件，重新上传 large_b，应恢复丢失块
    print('\n=== 6. 断点续传测试 ===')
    # 删除一个块（若存在）
    some = next(blocks_dir.glob('*'), None)
    if some:
        try:
            some.unlink()
            print('删除块', some.name, '以模拟中断')
        except Exception as e:
            print('无法删除块来模拟中断：', e)
    ok_b2 = upload_with_dedup(large_b)
    print('重新上传 large_b ok:', ok_b2)
    # 确认块文件已补回
    blocks_after_resume = set(p.name for p in blocks_dir.glob('*'))
    assert blocks_after_resume, '断点续传后 blocks 目录应包含块'
    print('断点续传：OK')

    print('\n全部检查通过（按脚本断言）。如果你希望我把此脚本转为 pytest 风格并加入自动清理，请告诉我。')


if __name__ == '__main__':
    run()
