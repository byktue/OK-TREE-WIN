# OK-TREE-WIN 本地运行指南

本指南聚合了你在 Windows 机器上启动 **后端 Java 服务** 和 **前端静态站点** 所需的全部步骤，按顺序执行即可在任何电脑上复现当前环境。

> 建议在仓库根目录（包含 `newbe/`、`OK-TREE-WIN Cloud-disk 前端 11.11/` 等子目录）打开终端；下文命令均使用相对路径，如路径不同可自行调整。

---

## 1. 准备前置依赖

| 组件 | 版本/要求 | 说明 |
| --- | --- | --- |
| JDK | 21（含 `java`、`javac`） | 用来跑 HttpFileServer（可安装 Oracle/OpenJDK/Temurin）。|
| Maven | 3.9+ | 用来编译 `newbe/modules` 里的 Java 项目。|
| Python | 3.x | 用来快速托管前端静态文件（`python -m http.server`）。|

确保上述命令在 PowerShell 中可用（`java -version`、`mvn -version`、`python --version`）。

---

## 2. 构建并运行后端

1. **进入后端模块目录并编译**
   ```powershell
    cd newbe\modules
   mvn clean package -DskipTests
   ```
   - 首次运行会下载依赖，完成后会生成 `target/file-server-1.0-SNAPSHOT.jar`。

2. **启动 HttpFileServer**
   ```powershell
    cd newbe
    java --enable-native-access=ALL-UNNAMED -cp "modules\target\file-server-1.0-SNAPSHOT.jar;modules\lib\*" HttpFileServer
   ```
   - 若成功，日志会提示“HTTP文件服务器已启动，监听端口：3000”。
   - 运行期间请保持该终端窗口开启；按 `Ctrl + C` 可停止服务器。
   - 如果你刚才仍停留在 `newbe\modules` 目录，请先执行 `cd ..` 返回 `newbe` 后再运行上述命令。

> **可选**：如果你使用的是系统全局 `java`，可以把命令里的 `java` 换成 JDK 的完整路径，确保运行的版本为 21。

---

## 3. 启动前端静态站点

1. **切换到前端代码目录**
   ```powershell
    cd "OK-TREE-WIN Cloud-disk 前端 11.11\1.全部代码（在此处打开运行）"
   ```
   - 从仓库根目录执行即可；若当前身在其它子目录，可使用 `cd ..` 返回根目录再运行。

2. **用 Python 启动本地静态服务器（端口 5500）**
   ```powershell
   python -m http.server 5500
   ```
   - 若需使用特定 Python，可指定绝对路径，例如：`E:/code_environment/python.exe -m http.server 5500`。
   - 正常情况下终端会显示 `Serving HTTP on :: port 5500 ...`。

3. **访问页面**
   - 登录页：`http://localhost:5500/login.html`
   - 文件管理页：`http://localhost:5500/file-manager.html`
   - 其余页面同理，将文件名追加在 `http://localhost:5500/` 之后即可。

4. **关闭前端服务器**
   - 在运行服务器的终端按 `Ctrl + C`。

> 如果 5500 端口已被占用，可替换为其它端口（例如 5501），然后在浏览器中使用对应端口。

---

## 4. 常见问题

| 情况 | 处理方式 |
| --- | --- |
| `Address already in use` | 换一个端口：`python -m http.server 5501`，浏览器改用 `http://localhost:5501/...`。 |
| 浏览器提示 “网络连接失败/Failed to fetch” | 确认后端 `java` 进程仍在运行并监听 `http://localhost:3000`；防火墙或代理也可能导致失败。 |
| 登录后刷新返回登录页 | 只能通过浏览器访问 `http://localhost:5500/...`（统一 HTTP 源），不要直接双击 `file-manager.html` 用 `file://` 打开。 |
| Maven 报缺少依赖 | 确认网络可访问 Maven 中央仓库，或配置代理；再执行 `mvn clean package -U -DskipTests`。 |

---

按照以上步骤，任何 Windows 电脑都可以快速启动 OK-TREE-WIN 的后端与前端，并保证浏览器使用统一的 HTTP 源。若需要批处理脚本或自动化工具，可在此基础上进一步封装。