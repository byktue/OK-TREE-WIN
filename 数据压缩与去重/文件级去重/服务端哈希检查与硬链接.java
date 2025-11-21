// 在HttpFileServer.java中拓展
// 新增哈希检查接口
server.createContext("/api/files/check-hash", new LoggingHandler(new HashCheckHandler()));

static class HashCheckHandler extends AbstractTokenHandler {
    @Override
    protected void handleWithAuth(HttpExchange exchange) throws IOException {
        String md5 = exchange.getRequestURI().getQuery().split("=")[1];
        Map<String, Object> response = new HashMap<>();
        
        try {
            dbLock.lock();
            PreparedStatement stmt = db.prepareStatement(
                "SELECT id, filepath FROM files WHERE md5 = ? AND is_deleted = 0");
            stmt.setString(1, md5);
            ResultSet rs = stmt.executeQuery();
            
            if (rs.next()) {
                // 文件已存在，返回文件ID并创建硬链接
                int existingFileId = rs.getInt("id");
                String existingPath = rs.getString("filepath");
                String newFileName = "link_" + System.currentTimeMillis() + "_" + userInfo.userId;
                String newPath = UPLOAD_DIR + File.separator + newFileName;
                
                // 创建硬链接（跨平台需要处理，Linux使用Files.createLink，Windows可能需要额外处理）
                Files.createLink(Paths.get(newPath), Paths.get(existingPath));
                
                // 插入新的文件记录（指向同一内容）
                PreparedStatement insertStmt = db.prepareStatement(
                    "INSERT INTO files (filename, filepath, filesize, md5, uploader_id) " +
                    "VALUES (?, ?, (SELECT filesize FROM files WHERE id = ?), ?, ?)");
                insertStmt.setString(1, newFileName);
                insertStmt.setString(2, newPath);
                insertStmt.setInt(3, existingFileId);
                insertStmt.setString(4, md5);
                insertStmt.setInt(5, userInfo.userId);
                insertStmt.executeUpdate();
                
                response.put("success", true);
                response.put("exists", true);
                response.put("fileId", existingFileId);
            } else {
                response.put("success", true);
                response.put("exists", false);
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", e.getMessage());
        } finally {
            dbLock.unlock();
        }
        sendResponse(exchange, 200, response);
    }
}