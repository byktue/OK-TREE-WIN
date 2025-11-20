// 在HttpFileServer.java中拓展
// 新增块级相关表（初始化数据库时添加）
stmt.execute("CREATE TABLE IF NOT EXISTS blocks (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "hash TEXT UNIQUE NOT NULL, " +
    "data_path TEXT NOT NULL, " +
    "size INTEGER NOT NULL)");

stmt.execute("CREATE TABLE IF NOT EXISTS file_blocks (" +
    "file_id INTEGER NOT NULL, " +
    "block_id INTEGER NOT NULL, " +
    "position INTEGER NOT NULL, " +
    "FOREIGN KEY(file_id) REFERENCES files(id), " +
    "FOREIGN KEY(block_id) REFERENCES blocks(id))");

// 块检查接口
static class BlockCheckHandler extends AbstractTokenHandler {
    @Override
    protected void handleWithAuth(HttpExchange exchange) throws IOException {
        // 解析客户端提交的块哈希列表
        JsonObject req = gson.fromJson(new InputStreamReader(exchange.getRequestBody()), JsonObject);
        List<String> hashes = gson.fromJson(req.get("hashes"), List.class);
        
        // 查询已有块哈希
        Set<String> existingHashes = new HashSet<>();
        try {
            dbLock.lock();
            PreparedStatement stmt = db.prepareStatement("SELECT hash FROM blocks WHERE hash IN (" +
                String.join(",", Collections.nCopies(hashes.size(), "?")) + ")");
            for (int i = 0; i < hashes.size(); i++) {
                stmt.setString(i+1, hashes.get(i));
            }
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                existingHashes.add(rs.getString("hash"));
            }
        } catch (SQLException e) {
            sendErrorResponse(exchange, 500, e.getMessage());
            return;
        } finally {
            dbLock.unlock();
        }
        
        // 计算缺失的块哈希
        List<String> missing = new ArrayList<>();
        for (String hash : hashes) {
            if (!existingHashes.contains(hash)) {
                missing.add(hash);
            }
        }
        
        sendResponse(exchange, 200, Map.of("success", true, "missing", missing));
    }
}

// 文件组装接口（合并块为完整文件）
static class FileAssembleHandler extends AbstractTokenHandler {
    @Override
    protected void handleWithAuth(HttpExchange exchange) throws IOException {
        JsonObject req = gson.fromJson(new InputStreamReader(exchange.getRequestBody()), JsonObject);
        String filename = req.get("filename").getAsString();
        List<String> blockHashes = gson.fromJson(req.get("block_hashes"), List.class);
        long totalSize = req.get("total_size").getAsLong();
        
        // 1. 创建文件记录
        int fileId = 0;
        try {
            dbLock.lock();
            PreparedStatement stmt = db.prepareStatement(
                "INSERT INTO files (filename, filepath, filesize, uploader_id) VALUES (?, ?, ?, ?)",
                Statement.RETURN_GENERATED_KEYS
            );
            String filePath = UPLOAD_DIR + File.separator + "assembled_" + System.currentTimeMillis();
            stmt.setString(1, filename);
            stmt.setString(2, filePath);
            stmt.setLong(3, totalSize);
            stmt.setInt(4, userInfo.userId);
            stmt.executeUpdate();
            
            ResultSet rs = stmt.getGeneratedKeys();
            if (rs.next()) {
                fileId = rs.getInt(1);
            }
            
            // 2. 记录块与文件的关联关系
            for (int i = 0; i < blockHashes.size(); i++) {
                PreparedStatement blockStmt = db.prepareStatement(
                    "INSERT INTO file_blocks (file_id, block_id, position) " +
                    "VALUES (?, (SELECT id FROM blocks WHERE hash = ?), ?)");
                blockStmt.setInt(1, fileId);
                blockStmt.setString(2, blockHashes.get(i));
                blockStmt.setInt(3, i);
                blockStmt.executeUpdate();
            }
            
            // 3. 合并块为完整文件
            try (FileOutputStream fos = new FileOutputStream(filePath)) {
                for (int i = 0; i < blockHashes.size(); i++) {
                    PreparedStatement dataStmt = db.prepareStatement(
                        "SELECT data_path FROM blocks WHERE hash = ?");
                    dataStmt.setString(1, blockHashes.get(i));
                    ResultSet dataRs = dataStmt.executeQuery();
                    if (dataRs.next()) {
                        Files.copy(Paths.get(dataRs.getString("data_path")), fos);
                    }
                }
            }
        } catch (Exception e) {
            sendErrorResponse(exchange, 500, e.getMessage());
            return;
        } finally {
            dbLock.unlock();
        }
        
        sendResponse(exchange, 200, Map.of("success", true, "fileId", fileId));
    }
}