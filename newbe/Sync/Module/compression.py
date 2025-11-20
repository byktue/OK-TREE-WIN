#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
压缩/解压工具（基于 gzip），用于在上传前压缩、下载后解压。
API:
  compress_file_to_bytes(path) -> bytes
  decompress_bytes_to_file(data_bytes, dest_path) -> None
"""
import gzip
from pathlib import Path

def compress_file_to_bytes(path: Path) -> bytes:
    path = Path(path)
    with open(path, 'rb') as f:
        data = f.read()
    return gzip.compress(data)

def decompress_bytes_to_file(data_bytes: bytes, dest_path: Path) -> None:
    dest_path = Path(dest_path)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    data = gzip.decompress(data_bytes)
    with open(dest_path, 'wb') as f:
        f.write(data)

def compress_stream_to_chunks(path: Path, chunk_size: int = 4 * 1024 * 1024):
    """Yield gzip-compressed chunks from file. Simpler: compress whole file then yield chunks."""
    comp = compress_file_to_bytes(path)
    for i in range(0, len(comp), chunk_size):
        yield comp[i:i+chunk_size]
