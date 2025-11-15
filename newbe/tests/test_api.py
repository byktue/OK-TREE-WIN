# -*- coding: utf-8 -*-
"""
集成测试脚本：测试 HttpFileServer 常用 API
使用说明见 README.md（同目录）

主要验证：
 - 注册 /api/auth/register
 - 登录 /api/auth/login
 - 获取/修改用户资料 /api/user/profile
 - 文件上传 /api/files/upload
 - 文件列表 /api/files
 - 文件下载 /api/files/download?fileId=...
 - 文件预览 /api/files/preview?fileId=...
 - 删除（移至回收站） /api/files/delete
 - 回收站列表/还原/清空 /api/recycle-bin ...
 - 修改密码 /api/user/change-password
 - 管理员删除用户 /api/admin/delete-user

运行前：确保服务在 http://localhost:3000 运行（默认端口3000）
"""

import requests
import uuid
import os
import sys
import time

BASE_URL = os.environ.get('BASE_URL', 'http://localhost:3000')
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PWD = os.environ.get('ADMIN_PWD', 'admin123')

# 简单断言与打印工具
def ok(msg):
    print(f"[OK] {msg}")

def fail(msg):
    print(f"[FAIL] {msg}")
    sys.exit(2)


def register(username, password):
    url = f"{BASE_URL}/api/auth/register"
    r = requests.post(url, json={"username": username, "password": password}, timeout=10)
    return r


def login(username, password):
    url = f"{BASE_URL}/api/auth/login"
    r = requests.post(url, json={"username": username, "password": password}, timeout=10)
    return r


def main():
    # 1. 生成测试用户
    username = f"test_{uuid.uuid4().hex[:8]}"
    password = "Test1234"
    new_password = "Test12345"
    print(f"使用测试用户: {username}")

    # 2. 注册
    r = register(username, password)
    if r.status_code != 200:
        # 可能用户名已存在（极少）或服务未启动
        fail(f"注册失败（HTTP {r.status_code}）：{r.text}")
    j = r.json()
    if not j.get('success'):
        fail(f"注册返回失败：{j}")
    ok("注册成功")

    # 3. 登录
    r = login(username, password)
    if r.status_code != 200:
        fail(f"登录失败（HTTP {r.status_code}）：{r.text}")
    j = r.json()
    token = j.get('token')
    if not token:
        fail(f"登录未返回 token：{j}")
    ok("登录成功，取得 token")
    headers = {'Authorization': f'Bearer {token}'}

    # 4. 获取用户资料
    r = requests.get(f"{BASE_URL}/api/user/profile", headers=headers, timeout=10)
    if r.status_code != 200:
        fail(f"获取资料失败：{r.status_code} {r.text}")
    j = r.json()
    data = j.get('data', {})
    if data.get('username') != username:
        fail(f"资料不匹配：{data}")
    ok("获取用户资料成功")

    # 5. 上传小文件
    files = {'file': ('hello.txt', b'hello world', 'text/plain')}
    r = requests.post(f"{BASE_URL}/api/files/upload", headers=headers, files=files, timeout=30)
    if r.status_code != 200:
        fail(f"上传失败：{r.status_code} {r.text}")
    j = r.json()
    if not j.get('success'):
        fail(f"上传返回失败：{j}")
    file_info = j.get('data')
    file_id = file_info.get('id')
    ok(f"上传成功，fileId={file_id}")

    # 6. 列表确认
    r = requests.get(f"{BASE_URL}/api/files", headers=headers, timeout=10)
    if r.status_code != 200:
        fail(f"查询文件列表失败：{r.status_code} {r.text}")
    j = r.json()
    files_list = j.get('data', [])
    found = any(f.get('id') == file_id for f in files_list)
    if not found:
        fail(f"上传的文件未出现在列表：{files_list}")
    ok("文件出现在列表中")

    # 7. 下载并校验内容
    r = requests.get(f"{BASE_URL}/api/files/download?fileId={file_id}", headers=headers, timeout=30)
    if r.status_code != 200:
        fail(f"下载失败：{r.status_code} {r.text}")
    content = r.content
    if content != b'hello world':
        fail(f"下载内容不匹配，期望 'hello world'，实际长度 {len(content)}")
    ok("下载并校验内容成功")

    # 8. 预览（文本）
    r = requests.get(f"{BASE_URL}/api/files/preview?fileId={file_id}", headers=headers, timeout=10)
    if r.status_code != 200:
        fail(f"预览失败：{r.status_code} {r.text}")
    j = r.json()
    preview = j.get('data', {}).get('content', '')
    if 'hello' not in preview:
        fail(f"预览内容不包含 hello：{preview}")
    ok("文件预览成功")

    # 9. 删除 -> 移至回收站
    r = requests.post(f"{BASE_URL}/api/files/delete", headers=headers, json={'fileId': file_id}, timeout=10)
    if r.status_code != 200:
        fail(f"删除失败：{r.status_code} {r.text}")
    ok("删除（移至回收站）成功")

    # 10. 回收站列表确认
    r = requests.get(f"{BASE_URL}/api/recycle-bin", headers=headers, timeout=10)
    if r.status_code != 200:
        fail(f"回收站查询失败：{r.status_code} {r.text}")
    j = r.json()
    recycle = j.get('data', [])
    found = any(f.get('id') == file_id for f in recycle)
    if not found:
        fail(f"被删除的文件未出现在回收站：{recycle}")
    ok("回收站列表包含被删除文件")

    # 11. 还原
    r = requests.post(f"{BASE_URL}/api/recycle-bin/restore", headers=headers, json={'fileId': file_id}, timeout=10)
    if r.status_code != 200:
        fail(f"还原失败：{r.status_code} {r.text}")
    ok("还原成功")

    # 12. 清空回收站（先删除再清空以验证接口）
    # 先再次删除
    r = requests.post(f"{BASE_URL}/api/files/delete", headers=headers, json={'fileId': file_id}, timeout=10)
    if r.status_code != 200:
        fail(f"第二次删除失败：{r.status_code} {r.text}")
    r = requests.post(f"{BASE_URL}/api/recycle-bin/empty", headers=headers, timeout=20)
    if r.status_code != 200:
        fail(f"清空回收站失败：{r.status_code} {r.text}")
    j = r.json()
    ok(f"清空回收站成功，返回：{j.get('data')}")

    # 13. 修改密码
    r = requests.post(f"{BASE_URL}/api/user/change-password", headers=headers, json={'oldPassword': password, 'newPassword': new_password}, timeout=10)
    if r.status_code != 200:
        fail(f"修改密码失败：{r.status_code} {r.text}")
    ok("修改密码成功")

    # 登录验证新密码
    r = login(username, new_password)
    if r.status_code != 200:
        fail(f"使用新密码登录失败：{r.status_code} {r.text}")
    ok("使用新密码登录成功")

    # 14. 管理员登录并删除测试用户（清理）
    r = login(ADMIN_USER, ADMIN_PWD)
    if r.status_code != 200:
        print("无法用管理员帐号登录以自动删除测试用户，请手动清理。")
        print(r.status_code, r.text)
        # 仍视为成功运行，但提醒清理
        ok("测试完成（未删除用户）")
        return
    admin_token = r.json().get('token')
    if not admin_token:
        print("管理员登录未返回 token，无法删除测试用户。请手动清理。")
        ok("测试完成（未删除用户）")
        return
    admin_headers = {'Authorization': f'Bearer {admin_token}'}
    r = requests.post(f"{BASE_URL}/api/admin/delete-user", headers=admin_headers, json={'username': username}, timeout=10)
    if r.status_code == 200:
        ok("管理员删除测试用户成功（已清理）")
    else:
        print(f"管理员删除用户失败（HTTP {r.status_code}）：{r.text}")
        print("请手动删除用户。")

    print("\n全部用例执行完毕。")


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        fail(f"脚本异常：{e}")
