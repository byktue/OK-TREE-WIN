
使用mvn安装相应依赖
```bash
mvn clean package -DskipTests
```

地址对应到后端文件夹
```bash
cd newbe
```

编译
```bash
javac -cp ".\lib\*;." -d .\out HttpFileServer.java
```

运行
```bash
java -cp ".\lib\*;.\out" HttpFileServer
```

