// 在HttpFileServer.java中拓展
// 文件上传处理器中添加压缩标识支持
static class FileUploadHandler extends AbstractTokenHandler {
    @Override
    protected void handleWithAuth(HttpExchange exchange) throws IOException {
        // 解析请求头判断是否为压缩文件
        boolean isCompressed = "gzip".equals(exchange.getRequestHeaders().getFirst("Content-Encoding"));
        
        // 现有文件保存逻辑...
        String savePath = UPLOAD_DIR + File.separator + uniqueFileName;
        if (isCompressed) {
            // 直接保存压缩文件（不解压，保留.gz后缀）
            savePath += ".gz";
        }
        
        // 数据库记录中添加压缩标识字段（需修改files表结构）
        try (PreparedStatement stmt = db.prepareStatement(
            "INSERT INTO files (filename, filepath, filesize, md5, uploader_id, is_compressed) VALUES (?, ?, ?, ?, ?, ?)")) {
            stmt.setString(1, originalFileName);
            stmt.setString(2, savePath);
            stmt.setLong(3, fileSize);
            stmt.setString(4, md5);
            stmt.setInt(5, userInfo.userId);
            stmt.setInt(6, isCompressed ? 1 : 0); // 新增压缩标识
            stmt.executeUpdate();
        }
    }
}

// 文件下载处理器添加压缩标识响应
static class FileDownloadHandler extends AbstractTokenHandler {
    @Override
    protected void handleWithAuth(HttpExchange exchange) throws IOException {
        // 现有文件查询逻辑...
        String filePath = rs.getString("filepath");
        boolean isCompressed = rs.getBoolean("is_compressed");
        
        // 响应头添加压缩标识
        if (isCompressed) {
            exchange.getResponseHeaders().set("Content-Encoding", "gzip");
        }
        
        // 现有文件传输逻辑...
    }
}