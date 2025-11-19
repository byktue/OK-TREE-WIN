# -*- coding: utf-8 -*-
"""
集成测试脚本：测试 HttpFileServer 常用 API
使用说明见 README.md（同目录）

主要验证：
 - 注册 /api/auth/register
 - 登录 /api/auth/login
 - 获取/修改用户资料 /api/user/profile
 - 文件上传 /api/files/upload（含空文件检测）
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

    # 5. 上传小文件（正常文件，非空）
    files = {'file': ('hello.txt', b'hello world', 'text/plain')}
    r = requests.post(f"{BASE_URL}/api/files/upload", headers=headers, files=files, timeout=30)
    if r.status_code != 200:
        fail(f"上传正常文件失败：{r.status_code} {r.text}")
    j = r.json()
    if not j.get('success'):
        fail(f"上传正常文件返回失败：{j}")
    normal_file_id = j.get('data').get('id')
    ok(f"正常文件上传成功，fileId={normal_file_id}")
    
    # -------------------------- 新增：空文件上传检测 --------------------------
    # 5.1 上传空文件（内容长度为0）
    empty_files = {'file': ('empty.txt', b'', 'text/plain')}  # 空字节内容
    r = requests.post(f"{BASE_URL}/api/files/upload", headers=headers, files=empty_files, timeout=30)

    # 两种预期场景（根据服务端设计选择一种校验逻辑）：
    # 场景1：服务端禁止上传空文件 → 应返回 4xx 错误（推荐）
    if r.status_code in [400, 403, 422]:
        j = r.json()
        # 适配服务端实际返回的错误信息：'文 件内容为空'（允许中间有空格）
        error_msg = j.get('message', '').replace(' ', '')  # 去除所有空格再匹配
        if '文件内容为空' in error_msg:
            ok(f"空文件上传被拒绝（符合预期）：{r.status_code} {j.get('message')}")
        else:
            fail(f"空文件上传被拒绝，但错误信息不明确：{j}")

    # 场景2：服务端允许上传空文件 → 验证文件大小为0
    elif r.status_code == 200:
        j = r.json()
        if not j.get('success'):
            fail(f"空文件上传返回失败：{j}")
        empty_file_id = j.get('data').get('id')
        # 校验服务端存储的文件大小是否为0
        r = requests.get(f"{BASE_URL}/api/files", headers=headers, timeout=10)
        files_list = r.json().get('data', [])
        empty_file = next((f for f in files_list if f.get('id') == empty_file_id), None)
        if not empty_file:
            fail(f"空文件上传后未出现在列表")
        # 验证文件大小（单位通常是字节）
        if empty_file.get('size', 0) != 0:
            fail(f"空文件大小异常：期望0字节，实际{empty_file.get('size')}字节")
        ok(f"空文件上传成功（服务端允许），fileId={empty_file_id}，大小0字节")

    # 场景3：服务端返回其他状态码 → 异常
    else:
        fail(f"空文件上传处理异常（HTTP {r.status_code}）：{r.text}")
    # -------------------------- 空文件上传检测结束 --------------------------
    
    # 6. 列表确认（正常文件存在）
    r = requests.get(f"{BASE_URL}/api/files", headers=headers, timeout=10)
    if r.status_code != 200:
        fail(f"查询文件列表失败：{r.status_code} {r.text}")
    j = r.json()
    files_list = j.get('data', [])
    normal_file_found = any(f.get('id') == normal_file_id for f in files_list)
    if not normal_file_found:
        fail(f"正常文件未出现在列表：{files_list}")
    ok("正常文件出现在列表中")

    # 7. 下载并校验正常文件内容
    r = requests.get(f"{BASE_URL}/api/files/download?fileId={normal_file_id}", headers=headers, timeout=30)
    if r.status_code != 200:
        fail(f"正常文件下载失败：{r.status_code} {r.text}")
    content = r.content
    if content != b'hello world':
        fail(f"正常文件下载内容不匹配，期望 'hello world'，实际长度 {len(content)}")
    ok("正常文件下载并校验内容成功")

    # 8. 预览（正常文件文本）
    r = requests.get(f"{BASE_URL}/api/files/preview?fileId={normal_file_id}", headers=headers, timeout=10)
    if r.status_code != 200:
        fail(f"正常文件预览失败：{r.status_code} {r.text}")
    j = r.json()
    preview = j.get('data', {}).get('content', '')
    if 'hello' not in preview:
        fail(f"正常文件预览内容不包含 hello：{preview}")
    ok("正常文件预览成功")

    # 9. 删除正常文件 -> 移至回收站
    r = requests.post(f"{BASE_URL}/api/files/delete", headers=headers, json={'fileId': normal_file_id}, timeout=10)
    if r.status_code != 200:
        fail(f"删除正常文件失败：{r.status_code} {r.text}")
    ok("删除正常文件（移至回收站）成功")

    # 10. 回收站列表确认
    r = requests.get(f"{BASE_URL}/api/recycle-bin", headers=headers, timeout=10)
    if r.status_code != 200:
        fail(f"回收站查询失败：{r.status_code} {r.text}")
    j = r.json()
    recycle = j.get('data', [])
    normal_file_in_recycle = any(f.get('id') == normal_file_id for f in recycle)
    if not normal_file_in_recycle:
        fail(f"正常文件未出现在回收站：{recycle}")
    ok("回收站列表包含正常文件")

    # 11. 还原正常文件
    r = requests.post(f"{BASE_URL}/api/recycle-bin/restore", headers=headers, json={'fileId': normal_file_id}, timeout=10)
    if r.status_code != 200:
        fail(f"还原正常文件失败：{r.status_code} {r.text}")
    ok("还原正常文件成功")

    # 12. 清空回收站（先删除再清空以验证接口）
    r = requests.post(f"{BASE_URL}/api/files/delete", headers=headers, json={'fileId': normal_file_id}, timeout=10)
    if r.status_code != 200:
        fail(f"第二次删除正常文件失败：{r.status_code} {r.text}")
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