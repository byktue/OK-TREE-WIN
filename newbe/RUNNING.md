```bash
mvn clean package -DskipTests
```

编译
```bash
javac -cp ".\lib\*;." -d .\out HttpFileServer.java
```

运行
```bash
java -cp ".\lib\*;.\out" HttpFileServer
```


# 快速运行说明（精简版）

下面是最小、可复制的步骤，在 Windows PowerShell 下按顺序执行即可启动 `HttpFileServer`。

1) 配置 Java（只需做一次）

```powershell
# 设置会话级 JAVA_HOME（替换为你自己的 JDK 路径）
$env:JAVA_HOME = 'C:\Program Files\Java\jdk-17'
$env:Path = $env:JAVA_HOME + '\bin;' + $env:Path
java -version
javac -version
```

2) （可选）设置 JWT 密钥（推荐在测试/生产使用相同密钥）

```powershell
$env:JWT_SECRET = '至少32字节的随机字符串_示例'
```

3) 构建（使用 Maven，可选）

```powershell
cd 'D:\Documents\大三课程\云计算系统\lab1\OK-TREE-WIN\newbe'
mvn clean package -DskipTests
# 构建成功后，jar 位于 target\file-server-1.0-SNAPSHOT.jar
```

4) 运行（二选一）

- 方法 A：运行 jar（推荐）

```powershell
cd 'D:\Documents\大三课程\云计算系统\lab1\OK-TREE-WIN\newbe'
java -jar .\target\file-server-1.0-SNAPSHOT.jar
```

- 方法 B：开发模式（classpath）

```powershell
cd 'D:\Documents\大三课程\云计算系统\lab1\OK-TREE-WIN\newbe'
java -cp ".\target\classes;.\n+\lib\*" HttpFileServer
```

5) 后台运行与日志

```powershell
java -jar .\target\file-server-1.0-SNAPSHOT.jar > server.log 2>&1
Get-Content .\server.log -Wait
```

6) 快速测试

```powershell
curl -X POST http://localhost:3000/api/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"admin123"}'
```

或者运行集成测试脚本（已包含在仓库）

```powershell
python -m pip install -r .\tests\requirements.txt
python .\tests\test_api.py
```

7) 常见问题速查

- 端口被占用：
  ```powershell
  netstat -ano | Select-String ":3000"
  taskkill /PID <pid> /F
  ```
- 找不到类：确保用 `-cp ".\\target\\classes;.\\lib\\*"` 或使用 fat-jar
- SQLite 锁定：停止其它进程或重启服务后再试
- 权限/磁盘空间：确保 `server_storage` 和 `recycle_bin` 可写

8) 常用命令速览

```powershell
# 构建
mvn clean package -DskipTests

# 运行
java -jar .\target\file-server-1.0-SNAPSHOT.jar

# 开发模式
java -cp ".\target\classes;.\lib\*" HttpFileServer

# 运行测试脚本
python -m pip install -r .\tests\requirements.txt
python .\tests\test_api.py
```

如果你要我把这个精简版保存在仓库的其他文件（如 `RUNNING_SUMMARY.md`）或现在在当前环境执行一次构建并运行测试，请告诉我。

