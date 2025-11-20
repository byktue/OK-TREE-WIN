#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
块级/文件级去重上传工具

流程（客户端）：
1. 计算文件 SHA256（作为文件指纹），向适配器查询 `/api/files/check?hash=...`。
   - 若存在，适配器返回已有文件 id，客户端直接完成同步（不上传内容）。
2. 否则：对文件进行 gzip 压缩，然后按 4MB 块切分压缩数据，计算每个块的 SHA256。
   - 向适配器 `/api/blocks/check` 提交块哈希列表，适配器返回缺失块。
   - 仅上传缺失的块到 `/api/blocks/upload`（multipart，带 hash 字段）。
   - 上传完成后调用 `/api/files/assemble` 提交文件元数据（relativePath、filename、chunks 列表、file_hash），适配器将块组装为最终文件并写入 DB。

返回：服务器上最终文件存在即视为上传成功（返回 True/False）。
"""
from pathlib import Path
import hashlib
import requests
import os
from typing import List
from auth import get_token
from config import get_config, SYNC_FOLDER
import logging
import gzip
try:
    from cryptography.fernet import Fernet
    HAVE_FERNET = True
except Exception:
    HAVE_FERNET = False

CHUNK_SIZE = 4 * 1024 * 1024

def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def sha256_of_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def get_headers():
    token = get_token()
    return {"Authorization": f"Bearer {token}"} if token else {}

def upload_with_dedup(local_path: Path) -> bool:
    adapter_base = get_config('adapter', 'base_url')
    # 1) 文件指纹
    file_hash = sha256_of_file(local_path)
    try:
        r = requests.get(f"{adapter_base}/api/files/check", params={'hash': file_hash}, headers=get_headers(), timeout=10)
        jr = r.json()
        if jr.get('exists'):
            # 如果服务器已有该文件，我们仍然需要确保块存储完整性：
            # 计算压缩后分块的 hash 列表，调用 /api/blocks/check 上传缺失块，
            # 然后再调用 assemble 创建指针记录。这能在删除块后通过另一端重传恢复块。
            try:
                try:
                    rel = str(local_path.relative_to(SYNC_FOLDER))
                except Exception:
                    rel = local_path.name

                # 计算压缩并分块（与后续流程一致）
                with open(local_path, 'rb') as f:
                    raw = f.read()
                try:
                    compressed = gzip.compress(raw)
                except Exception:
                    compressed = raw
                chunk_hashes_local: List[str] = []
                chunks_local: List[bytes] = []
                off = 0
                while off < len(compressed):
                    chunk = compressed[off:off + CHUNK_SIZE]
                    h = sha256_of_bytes(chunk)
                    chunk_hashes_local.append(h)
                    chunks_local.append(chunk)
                    off += CHUNK_SIZE

                # 可选加密
                encrypt_key = os.environ.get('SYNC_ENCRYPTION_KEY')
                fernet_local = None
                if encrypt_key and HAVE_FERNET:
                    try:
                        fernet_local = Fernet(encrypt_key)
                    except Exception:
                        fernet_local = None

                # 查询缺失块并上传
                print(f"CALL /api/blocks/check -> sending {len(chunk_hashes_local)} hashes (exists-branch)")
                try:
                    r2 = requests.post(f"{adapter_base}/api/blocks/check", json={'hashes': chunk_hashes_local}, headers=get_headers(), timeout=10)
                    missing_local = r2.json().get('missing', [])
                except Exception:
                    missing_local = chunk_hashes_local

                for idx, h in enumerate(chunk_hashes_local):
                    if h not in missing_local:
                        continue
                    data_bytes = chunks_local[idx]
                    if fernet_local:
                        try:
                            data_bytes = fernet_local.encrypt(data_bytes)
                        except Exception:
                            pass
                    files = {'chunk': ('chunk', data_bytes)}
                    data = {'hash': h}
                    print(f"UPLOAD block (exists-branch) {h} index={idx} size={len(data_bytes)}")
                    r3 = requests.post(f"{adapter_base}/api/blocks/upload", headers=get_headers(), files=files, data=data, timeout=60)
                    try:
                        jr3 = r3.json()
                    except Exception:
                        print('blocks/upload returned non-JSON in exists-branch', r3.status_code)
                        return False
                    if not jr3.get('success'):
                        print('blocks/upload failed in exists-branch for', h, jr3)
                        return False

                # 最后调用 assemble 创建指针记录（chunks 仍为空，因为文件已存在）
                payload = {'relativePath': rel, 'filename': local_path.name, 'chunks': [], 'file_hash': file_hash}
                print(f"files.check -> exists, after repairing blocks calling assemble with payload: {payload}")
                ra = requests.post(f"{adapter_base}/api/files/assemble", json=payload, headers=get_headers(), timeout=10)
                try:
                    jra = ra.json()
                except Exception:
                    print('assemble returned non-JSON in exists-branch', ra.status_code)
                    return False
                print('assemble response (exists-branch):', jra)
                return jra.get('success', False)
            except Exception as e:
                print('exists-branch exception:', e)
                return False
    except Exception:
        # 若适配器不可用或检查失败，回退到传统上传流程
        pass

    # 2) 先把整个文件 gzip 压缩（客户端使用压缩后数据切分块，有利于重复内容去重）
    #    然后按固定块分割压缩数据以进行块级去重 / 差分上传
    chunk_hashes: List[str] = []
    chunks: List[bytes] = []
    with open(local_path, 'rb') as f:
        raw = f.read()
    try:
        compressed = gzip.compress(raw)
    except Exception:
        compressed = raw
    # 切分压缩后的数据为块
    offset = 0
    while offset < len(compressed):
        chunk = compressed[offset:offset + CHUNK_SIZE]
        h = sha256_of_bytes(chunk)
        chunk_hashes.append(h)
        chunks.append(chunk)
        offset += CHUNK_SIZE

    # 可选：使用环境变量中的加密密钥对块进行加密（在上传前）
    encrypt_key = os.environ.get('SYNC_ENCRYPTION_KEY')
    fernet = None
    if encrypt_key and HAVE_FERNET:
        try:
            fernet = Fernet(encrypt_key)
        except Exception:
            fernet = None

    # 3) 查询缺失块
    try:
        print(f"CALL /api/blocks/check -> sending {len(chunk_hashes)} hashes")
        r = requests.post(f"{adapter_base}/api/blocks/check", json={'hashes': chunk_hashes}, headers=get_headers(), timeout=10)
        j = r.json()
        missing = j.get('missing', [])
        print(f"blocks.check response -> missing {len(missing)} blocks")
    except Exception:
        missing = chunk_hashes  # 保守假设全部缺失

    # 4) 上传缺失块（若配置加密则上传加密后数据，但 hash 是基于原始明文计算）
    for idx, h in enumerate(chunk_hashes):
        if h not in missing:
            continue
        try:
            data_bytes = chunks[idx]
            if fernet:
                try:
                    data_bytes = fernet.encrypt(data_bytes)
                except Exception:
                    pass
            files = {'chunk': ('chunk', data_bytes)}
            data = {'hash': h}
            print(f"UPLOAD block {h} (index {idx}) size={len(data_bytes)}")
            r = requests.post(f"{adapter_base}/api/blocks/upload", headers=get_headers(), files=files, data=data, timeout=60)
            try:
                jr = r.json()
            except Exception:
                print('blocks/upload returned non-JSON, status=', r.status_code)
                return False
            if not jr.get('success'):
                print('blocks/upload failed for', h, jr)
                return False
            print('blocks/upload succeeded for', h)
        except Exception:
            return False

    # 5) 调用 assemble
    rel = str(local_path.relative_to(SYNC_FOLDER)) if local_path.is_relative_to(SYNC_FOLDER) else local_path.name
    payload = {'relativePath': rel, 'filename': local_path.name, 'chunks': chunk_hashes, 'file_hash': file_hash}
    try:
        print(f"CALL /api/files/assemble with file_hash={file_hash} rel={rel} chunks={len(chunk_hashes)}")
        r = requests.post(f"{adapter_base}/api/files/assemble", json=payload, headers=get_headers(), timeout=30)
        jr = r.json()
        print('assemble response ->', jr)
        return jr.get('success', False)
    except Exception as e:
        print('assemble exception ->', e)
        return False
