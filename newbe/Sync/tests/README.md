# 后端 API 测试脚本

位置：`newbe/tests/test_api.py`

目的：对 `HttpFileServer` 的主要业务接口做端到端测试（注册、登录、文件上传/下载/删除/回收站、修改密码、管理员删除用户等）。

前提：
- 服务已启动并监听默认端口 3000（URL: http://localhost:3000）。
- 若端口或地址不同，请在运行前设置环境变量 `BASE_URL`。
- 若想使用非默认管理员账号，设置环境变量 `ADMIN_USER` 和 `ADMIN_PWD`。

快速开始（Windows PowerShell）：

1. 安装依赖（推荐在虚拟环境中运行）：

   python -m pip install -r .\requirements.txt

2. 启动服务（在项目根或 newbe 目录，根据你的启动方式）：

   # 例如使用打包好的 jar（假设在 newbe/target）
   cd ..\
   java -jar .\target\file-server-1.0-SNAPSHOT.jar

   # 或在 IDE 中运行 HttpFileServer.main

3. 在另一个终端运行测试脚本：

   python .\tests\test_api.py

环境变量（可选）：
- BASE_URL=http://localhost:3000
- ADMIN_USER=admin
- ADMIN_PWD=admin123

结果：
- 脚本会在控制台打印每一步的执行状态。若某一步失败，脚本会返回非 0 退出码并打印失败信息，便于定位问题。

注意事项：
- 脚本会尝试用管理员账号删除测试用户以清理数据；若管理员登录失败请手动清理数据库。
- 上传和下载部分对文件内容做了简单校验，适合快速回归测试。若需要更严格的兼容性测试，可扩展更多用例。
