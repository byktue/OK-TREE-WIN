文件结构:
```bash
│  checknew.py # 接口测试
│  HttpFileServer.java # 主文件
│  LoggingHandler.java # 日志装饰器：包装所有Handler，添加连接事件打印
│
└─lib # 编译时需要用到的java库
        gson-2.13.1.jar
        jackson-annotations-2.15.2.jar
        jackson-core-2.15.2.jar
        jackson-databind-2.15.2.jar
        java-jwt-4.5.0.jar
        jbcrypt-0.4.jar
        jjwt-api-0.13.0.jar
        jjwt-impl-0.13.0.jar
        jjwt-jackson-0.13.0.jar
        sqlite-jdbc-3.50.3.0.jar
```

windows上面运行
```bash
java -cp ".;lib/*" HttpFileServer.java
```

ubuntu
```bash
java -cp ".:lib/gson-2.13.1.jar:lib/sqlite-jdbc-3.50.3.0.jar" server.java
```


HttpFileServer.java中设置的端口是3000


京东云主机地址
117.72.99.242
用户名：root
密码：sdec-204421

使用WindTerm操作远程桌面

使用的京东云云主机，之前是windows系统的操作系统，重装成了Ubuntu22.04的Linux系统
但是原本的端口是windows的3389，要自己额外添加一个适合Linux的端口22
# 接口

HttpFileServer 可用接口汇总表

| 接口分类    | 接口路径                        | 请求方法 | 认证要求              | 核心功能描述                                             |
| ------- | --------------------------- | ---- | ----------------- | -------------------------------------------------- |
| 无需认证接口  | `/api/auth/login`           | POST | 无                 | 用户登录，验证用户名/密码，返回JWT Token及用户基础信息（ID、权限标识）          |
| 无需认证接口  | `/api/register`             | POST | 无                 | 新用户注册，创建普通用户账号（默认非管理员、非会员），用户名重复时返回错误              |
| 用户相关接口  | `/api/user/profile`         | GET  | 需JWT Token        | 获取当前登录用户的详细信息（用户名、昵称、邮箱、权限标识）                      |
| 用户相关接口  | `/api/user/profile`         | PUT  | 需JWT Token        | 修改当前登录用户的信息（仅支持修改昵称、邮箱）                            |
| 用户相关接口  | `/api/user/change-password` | POST | 需JWT Token        | 修改当前登录用户密码，需验证旧密码正确性，验证通过后更新为新密码                   |
| 文件管理接口  | `/api/files`                | GET  | 需JWT Token        | 获取当前用户上传的**未删除**文件列表，包含文件ID、文件名、大小、上传时间            |
| 文件管理接口  | `/api/files/upload`         | POST | 需JWT Token        | 上传文件（支持`multipart/form-data`格式），自动生成唯一文件名并记录MD5校验值 |
| 文件管理接口  | `/api/files/delete`         | POST | 需JWT Token        | 逻辑删除文件：将文件从上传目录移至回收站，更新数据库`is_deleted`状态为1         |
| 文件管理接口  | `/api/files/download`       | GET  | 需JWT Token        | 下载指定文件（需通过`?fileId=xxx`传参），校验文件完整性（大小、MD5）         |
| 文件管理接口  | `/api/files/preview`        | GET  | 需JWT Token        | 预览文本文件内容（仅支持.txt/.java等文本格式，限制前1KB内容）              |
| 回收站接口   | `/api/recycle-bin`          | GET  | 需JWT Token        | 获取当前用户回收站中的文件列表，包含文件ID、文件名、大小、删除时间                 |
| 回收站接口   | `/api/recycle-bin/restore`  | POST | 需JWT Token        | 还原回收站文件：将文件移回上传目录，更新数据库`is_deleted`状态为0            |
| 回收站接口   | `/api/recycle-bin/empty`    | POST | 需JWT Token        | 清空回收站：彻底删除物理文件及数据库中`is_deleted=1`的文件记录             |
| 管理员专属接口 | `/api/admin/delete-user`    | POST | 需JWT Token（管理员权限） | 删除指定普通用户（禁止删除admin账号），同时删除用户关联的所有文件（上传+回收站）        |

