#!/usr/bin/env python
# -*- coding:utf-8 -*-
import requests
from cryptography.fernet import Fernet
import os
from config import get_config, set_config, BASE_URL

# 加密密钥（首次运行自动生成）
KEY_FILE = os.path.join(os.path.expanduser("~"), ".netdisk_client", "secret.key")

def generate_key():
    """生成加密密钥"""
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

def load_key():
    """加载加密密钥"""
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()

# 初始化加密工具
cipher_suite = Fernet(load_key())

def encrypt_data(data: str) -> str:
    """加密数据"""
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    """解密数据"""
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except:
        return ""

def login(username: str, password: str) -> str:
    """登录服务端获取Token"""
    login_url = f"{BASE_URL}{get_config('server', 'login_path')}"
    try:
        response = requests.post(
            login_url,
            json={"username": username, "password": password},
            timeout=10
        )
        result = response.json()
        if result.get("success"):
            token = result.get("data", {}).get("token") or result.get("token")
            # 加密保存用户名、密码、Token
            set_config("auth", "username", encrypt_data(username))
            set_config("auth", "password", encrypt_data(password))
            set_config("auth", "token", token)
            return token
        else:
            print(f"登录失败：{result.get('message', '未知错误')}")
            return ""
    except Exception as e:
        print(f"登录请求异常：{str(e)}")
        return ""

def get_token() -> str:
    """获取本地存储的Token（自动刷新）"""
    token = get_config("auth", "token")
    if not token:
        # 从配置中解密用户名密码并重新登录
        username = decrypt_data(get_config("auth", "username"))
        password = decrypt_data(get_config("auth", "password"))
        if username and password:
            token = login(username, password)
    return token

def get_username() -> str:
    """返回本地保存的用户名（解密），如果没有则返回空字符串"""
    try:
        return decrypt_data(get_config("auth", "username"))
    except Exception:
        return ""

def refresh_token() -> str:
    """刷新Token（重新登录实现）"""
    username = decrypt_data(get_config("auth", "username"))
    password = decrypt_data(get_config("auth", "password"))
    return login(username, password) if username and password else ""

def logout():
    """退出登录（清空Token）"""
    set_config("auth", "token", "")
    print("已退出登录，Token已清空")