#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
去重与压缩端到端测试脚本

功能：
- 压缩上传：客户端对文件进行 gzip 压缩并上传（适配器保存压缩数据）。
- 文件级去重：上传相同内容的文件，适配器应避免重复存储（块/文件不会重复）。
- 块级去重：对大文件按 4MB 块上传，仅上传缺失块。

使用前提：
- 启动 `sync_adapter.py`（默认监听 4000），并确保 `Module/config.py` 中 adapter 地址正确。
"""
import sys
import time
from pathlib import Path


def prepare_module_path():
    repo_root = Path(__file__).resolve().parent.parent
    data_root = repo_root.parent / 'data'
    module_path = repo_root / 'Module'
    if str(module_path) not in sys.path:
        sys.path.insert(0, str(module_path))


def run():
    prepare_module_path()
    import config
    from auth import login
    import server_client
    from chunk_upload import upload_with_dedup

    repo_root = Path(__file__).resolve().parent.parent
    sync_folder = repo_root / 'test_sync_folder'
    sync_folder.mkdir(parents=True, exist_ok=True)
    config.set_sync_folder(str(sync_folder))

    print('尝试登录（test/test123）')
    try:
        login('test', 'test123')
    except Exception as e:
        print('登录忽略错误：', e)

    # 测试 1：小文件，文件级去重
    small1 = sync_folder / 'small1.txt'
    small1.write_text('hello dedup test', encoding='utf-8')
    print('上传 small1')
    ok1 = upload_with_dedup(small1)
    print('上传 small1 结果：', ok1)

    # 再上传同样内容的文件 small1_dup
    small_dup = sync_folder / 'small1_dup.txt'
    small_dup.write_text('hello dedup test', encoding='utf-8')
    print('上传 small1_dup（相同内容）')
    ok_dup = upload_with_dedup(small_dup)
    print('上传 small1_dup 结果：', ok_dup)

    # 测试 2：大文件，块级去重
    large_a = sync_folder / 'large_a.bin'
    large_b = sync_folder / 'large_b.bin'
    # 生成 10MB 的数据：large_a = AAAAA..., large_b = first half same as A, second half different
    half = 5 * 1024 * 1024
    a_bytes = (b'A' * (2 * half))
    b_bytes = (b'A' * half) + (b'B' * half)
    with open(large_a, 'wb') as f:
        f.write(a_bytes)
    with open(large_b, 'wb') as f:
        f.write(b_bytes)

    print('上传 large_a（触发分块上传）')
    ok_a = upload_with_dedup(large_a)
    print('上传 large_a 结果：', ok_a)

    print('上传 large_b（与 large_a 共享一半块）')
    ok_b = upload_with_dedup(large_b)
    print('上传 large_b 结果：', ok_b)

    # 等待适配器写入文件与块
    time.sleep(2)

    # 检查 blocks 目录与 files 列表
    blocks_dir = data_root / 'server_storage' / 'blocks'
    blocks = list(blocks_dir.glob('*')) if blocks_dir.exists() else []
    print(f'blocks 目录块数：{len(blocks)} (列举前20个)')
    for p in blocks[:20]:
        print(' -', p.name)

    files = server_client.list_cloud_files()
    print(f'云端文件数（当前用户视图）：{len(files)}')
    for item in files[:20]:
        print(' *', item)

    print('\n测试完成：请根据 blocks 数量与 files 列表判断去重是否生效。')


if __name__ == '__main__':
    run()
