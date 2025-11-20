#!/usr/bin/env python
# -*- coding:utf-8 -*-
import requests
from pathlib import Path
from auth import get_token, refresh_token
from config import BASE_URL, SYNC_FOLDER, get_config
try:
    from chunk_upload import upload_with_dedup
    from compression import decompress_bytes_to_file
except Exception:
    # best-effort import; functions may not be available in some contexts
    upload_with_dedup = None
    decompress_bytes_to_file = None

def get_headers() -> dict:
    """获取请求头（带Token）"""
    token = get_token()
    return {"Authorization": f"Bearer {token}"}

def upload_file(local_file_path: Path) -> bool:
    """上传文件到服务端"""
    if not local_file_path.exists() or local_file_path.is_dir():
        return False
    # 优先尝试 sync_adapter（独立存储）；若未启用或失败则回退到后端 Java 服务
    adapter_base = get_config('adapter', 'base_url')
    adapter_enabled = get_config('adapter', 'enabled').lower() == 'true'
    adapter_upload = f"{adapter_base}/api/files/upload"
    upload_url = f"{BASE_URL}{get_config('server', 'upload_path')}"
    try:
        relative_path = local_file_path.relative_to(SYNC_FOLDER)
    except Exception:
        # 当文件不在当前 SYNC_FOLDER 下（例如测试中改变了 sync folder），
        # 避免抛出 ValueError；回退到仅使用文件名作为相对路径。
        relative_path = Path(local_file_path.name)
    # 优先使用 adapter 的去重+分块上传（若可用）
    if adapter_enabled and upload_with_dedup:
        try:
            ok = upload_with_dedup(local_file_path)
            if ok:
                print(f"上传成功（adapter，去重/分块）：{local_file_path}")
                return True
            else:
                print(f"去重/分块上传失败，回退到普通上传：{local_file_path}")
        except Exception as ex:
            print(f"去重/分块上传异常：{ex}, 回退到普通上传")

    try:
        with open(local_file_path, "rb") as f:
            files = {"file": f}
            data = {"relativePath": str(relative_path), "filename": local_file_path.name}
            # 先尝试 adapter 的传统上传
            if adapter_enabled:
                try:
                    resp = requests.post(adapter_upload, headers=get_headers(), files=files, data=data, timeout=30)
                    jr = resp.json()
                    if jr.get('success'):
                        print(f"上传成功（adapter）：{local_file_path}")
                        return True
                    else:
                        # 如果 adapter 返回错误，打印并回退到主服务
                        print(f"adapter 上传失败：{jr.get('message')}")
                except Exception as ex:
                    print(f"调用 adapter 上传出错：{ex}")

            # 回退到后端 Java 服务
            response = requests.post(upload_url, headers=get_headers(), files=files, data=data, timeout=30)
            result = response.json()
            if result.get("success"):
                print(f"上传成功：{local_file_path}")
                return True
            else:
                # Token过期则刷新重试
                if "Token" in result.get("message", "") and "过期" in result.get("message", ""):
                    refresh_token()
                    response = requests.post(upload_url, headers=get_headers(), files=files, data=data, timeout=30)
                    return response.json().get("success", False)
                print(f"上传失败：{local_file_path}，原因：{result.get('message')}")
                return False
    except Exception as e:
        print(f"上传异常：{local_file_path}，原因：{str(e)}")
        return False

def delete_file(relative_path: str) -> bool:
    """删除服务端文件"""
    delete_url = f"{BASE_URL}{get_config('server', 'delete_path')}"
    try:
        response = requests.post(delete_url, headers=get_headers(), json={"relativePath": relative_path}, timeout=10)
        result = response.json()
        if result.get("success"):
            print(f"删除云端文件成功：{relative_path}")
            return True
        else:
            print(f"删除云端文件失败：{relative_path}，原因：{result.get('message')}")
            return False
    except Exception as e:
        print(f"删除异常：{str(e)}")
        return False

def list_cloud_files() -> list:
    """获取服务端文件列表"""
    adapter_base = get_config('adapter', 'base_url')
    adapter_enabled = get_config('adapter', 'enabled').lower() == 'true'
    adapter_list = f"{adapter_base}/api/files"
    list_url = f"{BASE_URL}{get_config('server', 'list_path')}"
    try:
        # 优先查询 adapter
        if adapter_enabled:
            try:
                response = requests.get(adapter_list, headers=get_headers(), timeout=10)
                result = response.json()
                if result.get('success'):
                    data = result.get('data', [])
                    # adapter 返回的是文件列表或包含 username 信息
                    if isinstance(data, list):
                        # 只返回当前用户的文件条目（adapter 会将 username 放入 data）
                        try:
                            from auth import get_username
                            cur_user = get_username()
                        except Exception:
                            cur_user = ''
                        if cur_user:
                            return [d for d in data if isinstance(d, dict) and d.get('username') == cur_user or (isinstance(d, dict) and not d.get('username'))]
                        return data
                # 若 adapter 返回不合预期，则继续回退到主服务
            except Exception as ex:
                print("调用 adapter list 失败：", ex)

        response = requests.get(list_url, headers=get_headers(), timeout=10)
        result = response.json()
        if not result.get("success"):
            return []
        data = result.get("data", [])
        # 兼容后端返回结构：data 可能是 dict 包含 files/breadcrumbs，也可能直接是文件列表
        if isinstance(data, dict) and "files" in data:
            files = data.get("files", [])
            try:
                from auth import get_username
                cur_user = get_username()
            except Exception:
                cur_user = ''
            if cur_user and isinstance(files, list):
                return [d for d in files if isinstance(d, dict) and d.get('username') == cur_user or (isinstance(d, dict) and not d.get('username'))]
            return files
        if isinstance(data, list):
            return data
        # 其它情况下，尝试从顶层直接返回 files
        if isinstance(result, dict) and "files" in result:
            return result.get("files", [])
        return []
    except Exception as e:
        print(f"获取云端文件列表异常：{str(e)}")
        return []


def check_server(timeout: int = 5) -> bool:
    """检查服务端是否可达（用于显示连接状态）"""
    adapter_base = get_config('adapter', 'base_url')
    adapter_enabled = get_config('adapter', 'enabled').lower() == 'true'
    list_url = f"{BASE_URL}{get_config('server', 'list_path')}"
    try:
        # 优先使用 adapter 进行连通性检查
        if adapter_enabled:
            try:
                resp = requests.get(f"{adapter_base}/api/files", headers=get_headers(), timeout=timeout)
                if resp.status_code == 200:
                    return True
            except Exception:
                pass
        response = requests.get(list_url, headers=get_headers(), timeout=timeout)
        # 如果服务器返回成功或 HTTP 200，认为可达
        if response.status_code == 200:
            try:
                result = response.json()
                return result.get("success", True)
            except Exception:
                return True
        return False
    except Exception as e:
        # 网络异常或连接失败
        print(f"服务连通性检查失败：{str(e)}")
        return False

def download_file(cloud_file: dict) -> bool:
    """从服务端下载文件到本地"""
    file_id = cloud_file.get("id")
    relative_path = cloud_file.get("relativePath", cloud_file.get("filename"))
    local_file_path = SYNC_FOLDER / relative_path
    adapter_base = get_config('adapter', 'base_url')
    adapter_enabled = get_config('adapter', 'enabled').lower() == 'true'
    download_url = f"{BASE_URL}{get_config('server', 'download_path')}?fileId={file_id}"
    # 若 adapter 可用，优先使用 adapter 的 download
    if adapter_enabled:
        download_url = f"{adapter_base}/api/files/download?fileId={file_id}"
    try:
        # 对 adapter 下载，读取全部内容后尝试解压（adapter 存储的是压缩后的内容）
        response = requests.get(download_url, headers=get_headers(), stream=False, timeout=60)
        if response.status_code == 200:
            local_file_path.parent.mkdir(exist_ok=True, parents=True)
            content = response.content
            # 若可用，使用 decompress_bytes_to_file 将压缩字节解压为目标文件
            if decompress_bytes_to_file:
                try:
                    decompress_bytes_to_file(content, local_file_path)
                    print(f"下载并解压成功：{local_file_path}")
                    return True
                except Exception:
                    # 解压失败，回退为直接写入（兼容未压缩的返回）
                    with open(local_file_path, 'wb') as f:
                        f.write(content)
                    print(f"下载成功（未解压）：{local_file_path}")
                    return True
            else:
                # 无解压器，直接写入
                with open(local_file_path, 'wb') as f:
                    f.write(content)
                print(f"下载成功：{local_file_path}")
                return True
        else:
            print(f"下载失败：{relative_path}，状态码：{response.status_code}")
            return False
    except Exception as e:
        print(f"下载异常：{relative_path}，原因：{str(e)}")
        return False