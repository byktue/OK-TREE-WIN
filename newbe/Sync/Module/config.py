#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
客户端配置模块
负责初始化配置文件、管理核心配置项、提供配置读写接口
"""
import os
import configparser
from pathlib import Path

# -------------------------- 配置文件基础路径 --------------------------
# 配置文件存储位置：用户主目录下的 .netdisk_client 文件夹
CONFIG_DIR = Path.home() / ".netdisk_client"
CONFIG_FILE = CONFIG_DIR / "config.ini"
# 确保配置目录存在
CONFIG_DIR.mkdir(exist_ok=True)

# -------------------------- 默认配置项（首次启动初始化用） --------------------------
DEFAULT_CONFIG = {
    "server": {
        # Java后端服务地址（需与后端实际端口一致）
        "base_url": "http://localhost:3000",
        # 后端各接口路径（与Java后端的接口路由对应）
        "login_path": "/api/auth/login",
        "upload_path": "/api/files/upload",
        "download_path": "/api/files/download",
        "delete_path": "/api/files/delete",
        "list_path": "/api/files",
        "profile_path": "/api/user/profile"
    },
    "sync": {
        # 本地同步文件夹路径（跨平台兼容，默认用户主目录下的「网盘同步文件夹」）
        "sync_folder": str(Path.home() / "网盘同步文件夹"),
        # 云端拉取同步的间隔（秒）：定时从服务端拉取文件变更
        "pull_interval": "60",
        # 忽略的临时文件后缀（用逗号分隔）：监控时跳过这些文件
        "skip_suffixes": ".tmp,~$, .swp, .bak, .DS_Store",
        # 是否递归监控同步文件夹的子目录
        "recursive_monitor": "True"
    },
    "auth": {
        # 登录凭证（首次启动为空，用户登录后自动保存）
        "username": "",
        "password": "",
        # JWT Token（登录后由后端返回，自动保存）
        "token": "",
        # Token过期时间（暂存，实际以后端返回的Token过期时间为准）
        "token_expire": ""
    },
    "log": {
        # 日志级别：DEBUG/INFO/WARNING/ERROR
        "level": "INFO",
        # 日志文件存储路径
        "log_file": str(CONFIG_DIR / "client.log")
    }
}

# 同步适配器（可选）：若使用独立的 sync_adapter 微服务，请将其地址配置到此处
DEFAULT_CONFIG["adapter"] = {
    "base_url": "http://localhost:4000",
    "enabled": "True"
}

# -------------------------- 配置解析器初始化 --------------------------
# 创建配置解析器对象
CONFIG = configparser.ConfigParser()

def init_config():
    """
    初始化配置文件
    若配置文件不存在，则创建并写入默认配置；若存在，则读取已有配置
    """
    if not CONFIG_FILE.exists():
        # 写入默认配置
        CONFIG.read_dict(DEFAULT_CONFIG)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            CONFIG.write(f)
        print(f"配置文件初始化完成，路径：{CONFIG_FILE}")
    else:
        # 读取已有配置
        CONFIG.read(CONFIG_FILE, encoding="utf-8")
        # 补全缺失的配置项（避免用户手动修改配置文件导致项缺失）
        for section in DEFAULT_CONFIG:
            if section not in CONFIG:
                CONFIG[section] = DEFAULT_CONFIG[section]
            for key in DEFAULT_CONFIG[section]:
                if key not in CONFIG[section]:
                    CONFIG[section][key] = DEFAULT_CONFIG[section][key]
        # 保存补全后的配置
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            CONFIG.write(f)
        print(f"配置文件加载完成，路径：{CONFIG_FILE}")

def get_config(section: str, key: str) -> str:
    """
    读取配置项
    :param section: 配置节（如 "server"、"sync"）
    :param key: 配置项键名
    :return: 配置项值
    """
    try:
        return CONFIG[section][key]
    except KeyError:
        # 若配置项缺失，返回默认值
        return DEFAULT_CONFIG[section][key]

def set_config(section: str, key: str, value: str):
    """
    修改并保存配置项
    :param section: 配置节
    :param key: 配置项键名
    :param value: 配置项值
    """
    if section not in CONFIG:
        CONFIG[section] = {}
    CONFIG[section][key] = value
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        CONFIG.write(f)
    print(f"配置项更新：{section}.{key} = {value}")

def get_sync_folder() -> Path:
    """
    获取本地同步文件夹路径（返回Path对象，方便文件操作）
    并确保同步文件夹存在
    """
    sync_folder = Path(get_config("sync", "sync_folder"))
    sync_folder.mkdir(exist_ok=True)
    return sync_folder

def set_sync_folder(path_str: str) -> Path:
    """
    设置并保存本地同步文件夹路径，同时更新模块级别的 SYNC_FOLDER 变量
    返回新的 Path 对象
    """
    set_config("sync", "sync_folder", path_str)
    new_path = Path(path_str)
    new_path.mkdir(exist_ok=True, parents=True)
    # 更新模块级常量
    global SYNC_FOLDER
    SYNC_FOLDER = new_path
    return SYNC_FOLDER

def get_skip_suffixes() -> list:
    """
    获取需要忽略的文件后缀列表（处理为字符串列表，方便监控模块使用）
    """
    suffixes = get_config("sync", "skip_suffixes")
    # 分割并去除空格
    return [s.strip() for s in suffixes.split(",") if s.strip()]

def get_pull_interval() -> int:
    """
    获取云端拉取间隔（转换为整数）
    """
    try:
        return int(get_config("sync", "pull_interval"))
    except ValueError:
        # 若配置项不是数字，返回默认值60
        return int(DEFAULT_CONFIG["sync"]["pull_interval"])

def is_recursive_monitor() -> bool:
    """
    判断是否递归监控同步文件夹的子目录（转换为布尔值）
    """
    return get_config("sync", "recursive_monitor").lower() == "true"

# -------------------------- 初始化配置（模块加载时自动执行） --------------------------
init_config()

# -------------------------- 对外暴露的常用配置常量（方便其他模块直接调用） --------------------------
# 服务端基础地址
BASE_URL = get_config("server", "base_url")
# 本地同步文件夹路径（Path对象）
SYNC_FOLDER = get_sync_folder()
# 忽略的文件后缀列表
SKIP_SUFFIXES = get_skip_suffixes()
# 云端拉取间隔（秒）
PULL_INTERVAL = get_pull_interval()
# 是否递归监控子目录
RECURSIVE_MONITOR = is_recursive_monitor()