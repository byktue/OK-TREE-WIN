编译
```bash
cd newbe\modules
mvn clean package -DskipTests
```

位于newbe,运行
```bash
cd ..
java --enable-native-access=ALL-UNNAMED -cp "modules\target\file-server-1.0-SNAPSHOT.jar;modules\lib\*" HttpFileServer
```

打开一个新的终端，进行端口代理
```bash
python -m http.server 5500
```

