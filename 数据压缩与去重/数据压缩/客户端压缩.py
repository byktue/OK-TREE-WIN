#客户端压缩
#在checknew.py中拓展
import gzip
import os

# 新增压缩工具方法
def compress_file(input_path, output_path):
    """使用GZIP压缩文件"""
    with open(input_path, 'rb') as f_in:
        with gzip.open(output_path, 'wb', compresslevel=6) as f_out:
            f_out.writelines(f_in)
    return output_path

def decompress_file(input_path, output_path):
    """解压GZIP文件"""
    with gzip.open(input_path, 'rb') as f_in:
        with open(output_path, 'wb') as f_out:
            f_out.writelines(f_in)
    return output_path

# 在文件上传前添加压缩逻辑（修改test_file_operations方法）
def test_file_operations(self):
    # ... 现有代码 ...
    
    # 4.2 上传文件 - 新增压缩步骤
    step = "文件压缩与上传"
    compressed_path = f"{TEST_FILE_PATH}.gz"
    try:
        # 压缩文件
        compress_file(TEST_FILE_PATH, compressed_path)
        # 上传压缩文件
        with open(compressed_path, 'rb') as f:
            files = {'file': (os.path.basename(compressed_path), f)}
            headers = {"Authorization": f"Bearer {self.user_token}"}
            upload_resp = requests.post(
                f"{self.base_url}/files/upload",
                files=files,
                headers=headers,
                timeout=10
            )
        # ... 处理响应 ...
    finally:
        # 清理临时文件
        if os.path.exists(compressed_path):
            os.remove(compressed_path)