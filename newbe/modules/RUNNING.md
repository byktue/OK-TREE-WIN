## 目录结构速览

```
newbe/
├─ HttpFileServer.java     # 唯一保留在根目录的核心运行入口
├─ data/                   # 仅存放运行期生成的数据
│  ├─ server_storage/      # 上传文件实体（含 uploads 子目录）
│  ├─ recycle_bin/         # 被删除文件暂存区
│  └─ file_server.db       # SQLite 数据库及其 wal/shm
└─ modules/                # 业务源码、依赖、脚本与构建文件
  ├─ *.java               # 业务 Handler、工具类等
  ├─ lib/                 # 依赖 Jar
  ├─ tests/               # Python 集成测试脚本
  ├─ RUNNING.md           # 即本文档
  └─ pom.xml              # Maven 构建脚本
```

> ✅ **记忆技巧**：来到 `newbe` 根目录时，可以看到 `HttpFileServer.java` + `data/`（纯数据）+ `modules/`（全部代码）。应用逻辑与依赖仍位于 `modules/` 内，存储数据被集中到 `data/`，方便备份与清理。

## 一键构建（推荐）

```powershell
cd 'D:\Documents\大三课程\云计算系统\lab1\OK-TREE-WIN\newbe\modules'
mvn clean package -DskipTests
```

编译完成后，`target/file-server-1.0-SNAPSHOT.jar` 会包含父目录中的 `HttpFileServer` 与 `modules` 里的所有 Handler/工具类。

## 手工编译 & 运行（无 Maven 时）

```powershell
cd 'D:\Documents\大三课程\云计算系统\lab1\OK-TREE-WIN\newbe'
$module = "modules"
Remove-Item -Recurse -Force "$module\out" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$module\out" | Out-Null
javac -cp "$module\lib\*;$module" -d "$module\out" $(Get-ChildItem "$module" -Filter *.java) .\HttpFileServer.java
java -cp "$module\lib\*;$module\out" HttpFileServer
```

> 提示：`Get-ChildItem` 会抓取 `modules` 内全部 `.java` 文件；若在 CMD 下，可改为 `for %f in (modules\*.java) do ...`。


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
cd 'D:\Documents\大三课程\云计算系统\lab1\OK-TREE-WIN\newbe\modules'
mvn clean package -DskipTests
# 构建成功后，jar 位于 modules\target\file-server-1.0-SNAPSHOT.jar
```

4) 运行（二选一）

- 方法 A：运行 jar（推荐）

```powershell
cd 'D:\Documents\大三课程\云计算系统\lab1\OK-TREE-WIN\newbe\modules'
java -jar .\target\file-server-1.0-SNAPSHOT.jar
```

- 方法 B：开发模式（classpath）

```powershell
cd 'D:\Documents\大三课程\云计算系统\lab1\OK-TREE-WIN\newbe'
java -cp ".\modules\target\classes;.\modules\lib\*" HttpFileServer
```

5) 后台运行与日志

```powershell
cd 'D:\Documents\大三课程\云计算系统\lab1\OK-TREE-WIN\newbe\modules'
java -jar .\target\file-server-1.0-SNAPSHOT.jar > ..\server.log 2>&1
Get-Content ..\server.log -Wait
```

6) 快速测试

```powershell
curl -X POST http://localhost:3000/api/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"admin123"}'
```

或者运行集成测试脚本（已包含在仓库）

```powershell
cd 'D:\Documents\大三课程\云计算系统\lab1\OK-TREE-WIN\newbe\modules'
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
- 权限/磁盘空间：确保 `data/server_storage` 和 `data/recycle_bin` 可写

8) 常用命令速览

```powershell
# 构建
cd 'D:\Documents\大三课程\云计算系统\lab1\OK-TREE-WIN\newbe\modules'
mvn clean package -DskipTests

# 运行
java -jar .\target\file-server-1.0-SNAPSHOT.jar

# 开发模式
cd ..
java -cp ".\modules\target\classes;.\modules\lib\*" HttpFileServer

# 运行测试脚本
cd .\modules
python -m pip install -r .\tests\requirements.txt
python .\tests\test_api.py
```

如果你要我把这个精简版保存在仓库的其他文件（如 `RUNNING_SUMMARY.md`）或现在在当前环境执行一次构建并运行测试，请告诉我。

