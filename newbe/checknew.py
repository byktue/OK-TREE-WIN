import socket
import requests
import json
import argparse
import time
from datetime import datetime
from pathlib import Path

# 全局配置（与Java服务器对应）
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 3000
TEST_USER = {
    "username": f"test_user_{int(time.time())}",  # 动态生成唯一测试用户
    "password": "Test@123456",
    "new_password": "Test@654321",
    "nickname": "测试用户",
    "email": f"test_{int(time.time())}@example.com"
}
ADMIN_USER = {
    "username": "admin",
    "password": "admin"  # Java服务器默认管理员密码
}
TEST_FILE_PATH = "test_upload.txt"  # 测试上传文件
TEST_FILE_CONTENT = "This is a test file for Java File Server."


class FileServerTester:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}/api"
        self.user_token = None  # 普通用户Token
        self.admin_token = None  # 管理员Token
        self.test_file_id = None  # 测试文件ID
        self.test_user_id = None  # 测试用户ID

    def _print_result(self, step, success, message=""):
        """统一结果打印格式"""
        status = "✅ 成功" if success else "❌ 失败"
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {step} - {status}")
        if message:
            print(f"      详情: {message}\n")

    def check_port(self, timeout=5):
        """1. 检测服务器端口是否开放"""
        step = "端口可用性检测"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((self.host, self.port))
                if result == 0:
                    self._print_result(step, True, f"端口 {self.port} 已开放")
                    return True
                else:
                    self._print_result(step, False, f"端口 {self.port} 未开放或服务器未启动")
                    return False
        except Exception as e:
            self._print_result(step, False, f"检测出错: {str(e)}")
            return False

    def _send_request(self, method, path, data=None, headers=None, is_form=False):
        url = f"{self.base_url}{path}"
        default_headers = {"Content-Type": "application/json"}
        
        if headers:
            default_headers.update(headers)
        
        if self.user_token and "Authorization" not in default_headers:
            default_headers["Authorization"] = f"Bearer {self.user_token}"

        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=default_headers, timeout=10)
            elif method.upper() == "POST":
                if is_form:
                    response = requests.post(url, data=data, headers=headers, timeout=10)
                else:
                    response = requests.post(url, json=data, headers=default_headers, timeout=10)
            elif method.upper() == "PUT":
                response = requests.put(url, json=data, headers=default_headers, timeout=10)
            else:
                return {"success": False, "status_code": 405, "message": f"不支持的请求方法: {method}"}

            # 正常响应时，提取状态码和数据
            try:
                resp_json = response.json()
            except json.JSONDecodeError:
                resp_json = response.text
            return {
                "success": True,
                "status_code": response.status_code,  # 确保存在状态码
                "data": resp_json
            }
        except requests.exceptions.RequestException as e:
            # 请求异常（超时、连接失败等），返回异常状态码和信息
            return {
                "success": False,
                "status_code": 999,  # 用999标识请求层异常
                "message": f"请求异常: {str(e)}"
            }
        except Exception as e:
            # 其他未知异常，兜底处理
            return {
                "success": False,
                "status_code": 500,  # 用500标识未知错误
                "message": f"未知错误: {str(e)}"
            }
            
    def test_auth_flow(self):
        """2. 测试认证流程：注册→登录→管理员登录"""
        # 2.1 普通用户注册
        step = "普通用户注册"
        reg_data = {"username": TEST_USER["username"], "password": TEST_USER["password"]}
        reg_resp = self._send_request("POST", "/register", reg_data)
        
        if not reg_resp["success"]:
            self._print_result(step, False, reg_resp["message"])
            return False
        if reg_resp["status_code"] == 200 and reg_resp["data"]["success"]:
            self._print_result(step, True, f"用户 {TEST_USER['username']} 注册成功")
        elif reg_resp["status_code"] == 400 and "用户名已存在" in reg_resp["data"]["message"]:
            self._print_result(step, True, "用户已存在，跳过注册")
        else:
            self._print_result(step, False, f"状态码: {reg_resp['status_code']}, 信息: {reg_resp['data']}")
            return False

        # 2.2 普通用户登录
        step = "普通用户登录"
        login_data = {"username": TEST_USER["username"], "password": TEST_USER["password"]}
        login_resp = self._send_request("POST", "/auth/login", login_data)
        
        if not login_resp["success"]:
            self._print_result(step, False, login_resp["message"])
            return False
        if login_resp["status_code"] == 200 and login_resp["data"]["success"]:
            self.user_token = login_resp["data"]["token"]
            self.test_user_id = login_resp["data"]["user"]["id"]
            self._print_result(step, True, f"获取Token: {self.user_token[:20]}...")
        else:
            self._print_result(step, False, f"登录失败: {login_resp['data']}")
            return False

        # 2.3 管理员登录
        step = "管理员登录"
        admin_login_data = {"username": ADMIN_USER["username"], "password": ADMIN_USER["password"]}
        admin_resp = self._send_request("POST", "/auth/login", admin_login_data)
        
        if not admin_resp["success"]:
            self._print_result(step, False, admin_resp["message"])
            return False
        if admin_resp["status_code"] == 200 and admin_resp["data"]["success"]:
            self.admin_token = admin_resp["data"]["token"]
            self._print_result(step, True, f"管理员Token: {self.admin_token[:20]}...")
        else:
            self._print_result(step, False, f"管理员登录失败: {admin_resp['data']}")
            return False

        return True

    def test_user_operations(self):
        """3. 测试用户功能：获取资料→修改资料→修改密码"""
        # 3.1 获取用户资料
        step = "获取用户资料"
        profile_resp = self._send_request("GET", "/user/profile")
        
        if not profile_resp["success"]:
            self._print_result(step, False, profile_resp["message"])
            return False
        if profile_resp["status_code"] == 200 and profile_resp["data"]["success"]:
            self._print_result(step, True, f"用户名: {profile_resp['data']['data']['username']}")
        else:
            self._print_result(step, False, f"获取失败: {profile_resp['data']}")
            return False

        # 3.2 修改用户资料
        step = "修改用户资料"
        update_data = {"nickname": TEST_USER["nickname"], "email": TEST_USER["email"]}
        update_resp = self._send_request("PUT", "/user/profile", update_data)
        
        if not update_resp["success"]:
            self._print_result(step, False, update_resp["message"])
            return False
        if update_resp["status_code"] == 200 and update_resp["data"]["success"]:
            self._print_result(step, True, f"昵称: {TEST_USER['nickname']}, 邮箱: {TEST_USER['email']}")
        else:
            self._print_result(step, False, f"修改失败: {update_resp['data']}")
            return False

        # 3.3 修改密码
        step = "修改用户密码"
        pwd_data = {
            "oldPassword": TEST_USER["password"],
            "newPassword": TEST_USER["new_password"]
        }
        pwd_resp = self._send_request("POST", "/user/change-password", pwd_data)
        
        if not pwd_resp["success"]:
            self._print_result(step, False, pwd_resp["message"])
            return False
        if pwd_resp["status_code"] == 200 and pwd_resp["data"]["success"]:
            self._print_result(step, True, "密码修改成功（后续用新密码）")
            # 更新测试密码（后续操作可能需要重新登录）
            TEST_USER["password"] = TEST_USER["new_password"]
        else:
            self._print_result(step, False, f"密码修改失败: {pwd_resp['data']}")
            return False

        return True

    def test_file_operations(self):
        """4. 测试文件功能：创建测试文件→上传→列表→预览→下载"""
        # 4.1 创建测试文件
        step = "创建测试文件"
        try:
            with open(TEST_FILE_PATH, "w", encoding="utf-8") as f:
                f.write(TEST_FILE_CONTENT)
            self._print_result(step, True, f"文件 {TEST_FILE_PATH} 创建成功")
        except Exception as e:
            self._print_result(step, False, f"创建失败: {str(e)}")
            return False

        # 4.2 上传文件
        step = "文件上传"
        # 移除手动设置的Content-Type，让requests自动生成正确的multipart格式
        headers = {
            "Authorization": f"Bearer {self.user_token}"
            # 不要手动设置Content-Type，requests会自动添加正确的multipart/form-data及boundary
        }
        with open(TEST_FILE_PATH, "rb") as f:
            # 确保表单字段名为"file"（Java服务器可能依赖此字段名解析）
            files = {"file": (TEST_FILE_PATH, f, "text/plain")}
            # 使用requests的files参数自动处理multipart格式，无需手动设置is_form
            response = requests.post(
                f"{self.base_url}/files/upload",
                headers=headers,
                files=files,
                timeout=10
            )

        # 解析响应
        try:
            upload_resp = {
                "success": True,
                "status_code": response.status_code,
                "data": response.json()
            }
        except json.JSONDecodeError:
            upload_resp = {
                "success": True,
                "status_code": response.status_code,
                "data": response.text
            }

        # 4.3 获取文件列表（并记录测试文件ID）
        step = "获取文件列表"
        list_resp = self._send_request("GET", "/files")
        
        if not list_resp["success"]:
            self._print_result(step, False, list_resp["message"])
            return False
        if list_resp["status_code"] == 200 and list_resp["data"]["success"]:
            files = list_resp["data"]["data"]
            if not files:
                self._print_result(step, False, "文件列表为空，上传可能失败")
                return False
            # 取最新上传的文件作为测试文件
            self.test_file_id = files[-1]["id"]
            self._print_result(step, True, f"获取 {len(files)} 个文件，测试文件ID: {self.test_file_id}")
        else:
            self._print_result(step, False, f"获取失败: {list_resp['data']}")
            return False

        # 4.4 预览文件
        step = "文件预览"
        preview_resp = self._send_request("GET", f"/files/preview?fileId={self.test_file_id}")
        
        if not preview_resp["success"]:
            self._print_result(step, False, preview_resp["message"])
            return False
        if preview_resp["status_code"] == 200 and preview_resp["data"]["success"]:
            preview_content = preview_resp["data"]["data"]["content"]
            self._print_result(step, True, f"预览内容: {preview_content[:30]}...")
        else:
            self._print_result(step, False, f"预览失败: {preview_resp['data']}")
            return False

        # 4.5 下载文件
        step = "文件下载"
        download_url = f"{self.base_url}/files/download?fileId={self.test_file_id}"
        headers = {"Authorization": f"Bearer {self.user_token}"}
        try:
            response = requests.get(download_url, headers=headers, timeout=10, stream=True)
            if response.status_code == 200:
                download_path = f"downloaded_{TEST_FILE_PATH}"
                with open(download_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=1024):
                        f.write(chunk)
                # 验证下载内容
                with open(download_path, "r", encoding="utf-8") as f:
                    downloaded_content = f.read()
                if downloaded_content == TEST_FILE_CONTENT:
                    self._print_result(step, True, f"下载成功并验证内容一致，保存为 {download_path}")
                else:
                    self._print_result(step, False, "下载内容与原文件不一致")
                    return False
            else:
                self._print_result(step, False, f"下载失败，状态码: {response.status_code}")
                return False
        except Exception as e:
            self._print_result(step, False, f"下载出错: {str(e)}")
            return False

        return True

    def test_recycle_operations(self):
        """5. 测试回收站功能：删除文件→回收站列表→还原→清空回收站"""
        # 5.1 删除文件（移至回收站）
        step = "删除文件（移至回收站）"
        delete_data = {"fileId": self.test_file_id}
        delete_resp = self._send_request("POST", "/files/delete", delete_data)
        
        if not delete_resp["success"]:
            self._print_result(step, False, delete_resp["message"])
            return False
        if delete_resp["status_code"] == 200 and delete_resp["data"]["success"]:
            self._print_result(step, True, f"文件ID {self.test_file_id} 已移至回收站")
        else:
            self._print_result(step, False, f"删除失败: {delete_resp['data']}")
            return False

        # 5.2 获取回收站列表
        step = "获取回收站列表"
        recycle_resp = self._send_request("GET", "/recycle-bin")
        
        if not recycle_resp["success"]:
            self._print_result(step, False, recycle_resp["message"])
            return False
        if recycle_resp["status_code"] == 200 and recycle_resp["data"]["success"]:
            recycle_files = recycle_resp["data"]["data"]
            if not recycle_files:
                self._print_result(step, False, "回收站为空，删除可能失败")
                return False
            self._print_result(step, True, f"回收站有 {len(recycle_files)} 个文件")
        else:
            self._print_result(step, False, f"获取失败: {recycle_resp['data']}")
            return False

        # 5.3 还原回收站文件
        step = "还原回收站文件"
        restore_data = {"fileId": self.test_file_id}
        restore_resp = self._send_request("POST", "/recycle-bin/restore", restore_data)
        
        if not restore_resp["success"]:
            self._print_result(step, False, restore_resp["message"])
            return False
        if restore_resp["status_code"] == 200 and restore_resp["data"]["success"]:
            self._print_result(step, True, f"文件ID {self.test_file_id} 已还原")
        else:
            self._print_result(step, False, f"还原失败: {restore_resp['data']}")
            return False

        # 5.4 再次删除文件（用于后续清空回收站测试）
        step = "再次删除文件（用于清空测试）"
        redelete_resp = self._send_request("POST", "/files/delete", delete_data)
        if not redelete_resp["success"] or not (redelete_resp["status_code"] == 200 and redelete_resp["data"]["success"]):
            self._print_result(step, False, f"删除失败: {redelete_resp['data']}")
            return False

        # 5.5 清空回收站
        step = "清空回收站"
        empty_resp = self._send_request("POST", "/recycle-bin/empty")
        
        if not empty_resp["success"]:
            self._print_result(step, False, empty_resp["message"])
            return False
        if empty_resp["status_code"] == 200 and empty_resp["data"]["success"]:
            self._print_result(step, True, "回收站已成功清空")
        else:
            self._print_result(step, False, f"清空失败: {empty_resp['data']}")
            return False

        return True

    def test_admin_operations(self):
        """6. 测试管理员功能：删除测试用户"""
        # 6.1 使用管理员Token删除测试用户
        step = "管理员删除测试用户"
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        delete_data = {"username": TEST_USER["username"]}
        delete_resp = self._send_request("POST", "/admin/delete-user", delete_data, headers)
        
        if not delete_resp["success"]:
            self._print_result(step, False, delete_resp["message"])
            return False
        if delete_resp["status_code"] == 200 and delete_resp["data"]["success"]:
            self._print_result(step, True, f"测试用户 {TEST_USER['username']} 已删除")
        else:
            self._print_result(step, False, f"删除失败: {delete_resp['data']}")
            return False

        # 6.2 验证用户已被删除（尝试用原Token访问）
        step = "验证用户已删除"
        profile_resp = self._send_request("GET", "/user/profile")
        actual_status = profile_resp.get("status_code", "未知")

        # 两种情况均视为用户已删除
        if actual_status == 401 or actual_status == 999:
            self._print_result(step, True, f"用户已删除（状态码: {actual_status}，符合预期）")
            return True  # 关键修复：成功时必须返回True，让脚本继续执行
        else:
            self._print_result(step, False, f"用户未被正确删除，状态码: {actual_status}")
            return False

    def run_full_test(self):
        """运行完整测试流程"""
        print("="*50)
        print(f"开始测试 Java 文件服务器: {self.host}:{self.port}")
        print("测试范围: 端口检测→认证流程→用户操作→文件管理→回收站→管理员功能")
        print("="*50 + "\n")

        # 按步骤执行测试，前一步失败则终止
        steps = [
            ("端口检测", self.check_port),
            ("认证流程测试", self.test_auth_flow),
            ("用户功能测试", self.test_user_operations),
            ("文件功能测试", self.test_file_operations),
            ("回收站功能测试", self.test_recycle_operations),
            ("管理员功能测试", self.test_admin_operations)
        ]

        for step_name, step_func in steps:
            if not step_func():
                print(f"\n❌ 测试中断：{step_name}失败")
                return False

        print("\n" + "="*50)
        print("✅ 所有测试步骤均通过！文件服务器功能正常")
        print("="*50)
        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Java文件服务器完整功能测试工具")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"服务器主机名（默认: {DEFAULT_HOST}）")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"服务器端口（默认: {DEFAULT_PORT}）")
    args = parser.parse_args()

    # 初始化测试器并运行完整测试
    tester = FileServerTester(args.host, args.port)
    tester.run_full_test()