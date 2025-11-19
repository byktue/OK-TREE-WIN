编译
```bash
cd newbe\modules
mvn clean package -DskipTests
```

运行
```bash
cd ..
java --enable-native-access=ALL-UNNAMED -cp "modules\target\file-server-1.0-SNAPSHOT.jar;modules\lib\*" HttpFileServer
```

端口代理
```bash
cd ..
cd "OK-TREE-WIN Cloud-disk 前端 11.11\1.全部代码（在此处打开运行）"
python -m http.server 5500
```
