#块级去重客户端
#在checknew.py中扩展
def split_file(file_path, block_size=4*1024*1024):
    """将文件分割为固定大小块（4MB）"""
    blocks = []
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(block_size)
            if not chunk:
                break
            block_hash = hashlib.sha256(chunk).hexdigest()
            blocks.append({"hash": block_hash, "data": chunk})
    return blocks

def test_block_upload(self):
    # 分块处理
    blocks = split_file(TEST_FILE_PATH)
    block_hashes = [b["hash"] for b in blocks]
    
    # 检查服务器已有块
    check_resp = self._send_request("POST", "/files/check-blocks", {"hashes": block_hashes})
    missing_hashes = check_resp["data"]["missing"]
    
    # 仅上传缺失的块
    for block in blocks:
        if block["hash"] in missing_hashes:
            self._send_request(
                "POST", 
                "/files/upload-block", 
                data={"hash": block["hash"]},
                files={"block_data": block["data"]},
                is_form=True
            )
    
    # 提交文件元数据（块哈希列表）
    self._send_request(
        "POST", 
        "/files/assemble", 
        {
            "filename": TEST_FILE_PATH,
            "block_hashes": block_hashes,
            "total_size": os.path.getsize(TEST_FILE_PATH)
        }
    )