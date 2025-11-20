#文件及去重客户端
#在checknew.py中扩展
def test_file_operations(self):
    # ... 现有代码 ...
    
    # 4.1.1 计算文件哈希
    step = "计算文件哈希"
    import hashlib
    md5_hash = hashlib.md5()
    with open(TEST_FILE_PATH, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    file_md5 = md5_hash.hexdigest()
    self._print_result(step, True, f"文件MD5: {file_md5}")
    
    # 4.1.2 检查服务器是否存在该哈希文件
    step = "文件哈希预检查"
    check_resp = self._send_request("GET", f"/files/check-hash?md5={file_md5}")
    if check_resp["status_code"] == 200 and check_resp["data"]["exists"]:
        self._print_result(step, True, "文件已存在，无需重复上传")
        self.test_file_id = check_resp["data"]["fileId"]
        return True  # 跳过实际上传步骤
    else:
        self._print_result(step, True, "文件不存在，准备上传")