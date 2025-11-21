import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 回收站相关 Handler。
 */
public final class RecycleHandlers {
    private RecycleHandlers() {}

    public static class RecycleBinHandler extends AbstractTokenHandler {
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持GET方法");
                return;
            }

            try {
                dbLock.lock();
                PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                        "SELECT id, filename, filesize, delete_time FROM files " +
                        "WHERE uploader_id = ? AND is_deleted = 1 ORDER BY delete_time DESC");
                pstmt.setInt(1, userInfo.userId);
                ResultSet rs = pstmt.executeQuery();

                List<Map<String, Object>> recycleList = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> file = new HashMap<>();
                    file.put("id", rs.getInt("id"));
                    file.put("filename", rs.getString("filename"));
                    file.put("fileSize", rs.getLong("filesize"));
                    file.put("deleteTime", rs.getString("delete_time"));
                    recycleList.add(file);
                }

                sendSuccessResponse(exchange, recycleList);
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().info("用户查询回收站：" + userInfo.username + "（文件数：" + recycleList.size() + "）");
                }
            } catch (SQLException e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("查询回收站异常：" + e.getMessage());
                }
                sendErrorResponse(exchange, 500, "服务器内部错误");
            } finally {
                dbLock.unlock();
            }
        }
    }

    public static class RestoreHandler extends AbstractTokenHandler {
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                JsonObject req = gson.fromJson(br, JsonObject.class);
                if (!req.has("fileId")) {
                    sendErrorResponse(exchange, 400, "缺少参数：fileId");
                    return;
                }
                int fileId = req.get("fileId").getAsInt();

                dbLock.lock();
                try {
                    PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                            "SELECT filename FROM files WHERE id = ? AND uploader_id = ? AND is_deleted = 1");
                    pstmt.setInt(1, fileId);
                    pstmt.setInt(2, userInfo.userId);
                    ResultSet rs = pstmt.executeQuery();

                    if (!rs.next()) {
                        sendErrorResponse(exchange, 404, "文件不存在或无权限");
                        return;
                    }
                    String filename = rs.getString("filename");

                    Path sourcePath = Paths.get(HttpFileServer.RECYCLE_DIR + java.io.File.separator + filename);
                    Path targetPath = Paths.get(HttpFileServer.UPLOAD_DIR + java.io.File.separator + filename);

                    if (Files.exists(targetPath)) {
                        String timestamp = String.valueOf(System.currentTimeMillis());
                        String newFilename = timestamp + "_" + filename;
                        targetPath = Paths.get(HttpFileServer.UPLOAD_DIR + java.io.File.separator + newFilename);
                        try (PreparedStatement updateStmt = ServerContext.getConnection().prepareStatement(
                                "UPDATE files SET filename = ? WHERE id = ?")) {
                            updateStmt.setString(1, newFilename);
                            updateStmt.setInt(2, fileId);
                            updateStmt.executeUpdate();
                        }
                    }

                    Files.move(sourcePath, targetPath, StandardCopyOption.REPLACE_EXISTING);

                    try (PreparedStatement updateStmt = ServerContext.getConnection().prepareStatement(
                            "UPDATE files SET is_deleted = 0, delete_time = NULL, filepath = ? WHERE id = ?")) {
                        updateStmt.setString(1, targetPath.toString());
                        updateStmt.setInt(2, fileId);
                        updateStmt.executeUpdate();
                    }

                    sendSuccessResponse(exchange, null);
                    if (ServerContext.getLogger() != null) {
                        ServerContext.getLogger().info("用户还原文件：" + userInfo.username + "（文件：" + filename + "）");
                    }
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("还原文件异常：" + e.getMessage());
                }
                sendErrorResponse(exchange, 500, "文件还原失败：" + e.getMessage());
            }
        }
    }

    public static class EmptyRecycleHandler extends AbstractTokenHandler {
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            try {
                dbLock.lock();
                PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                        "SELECT filename FROM files WHERE uploader_id = ? AND is_deleted = 1");
                pstmt.setInt(1, userInfo.userId);
                ResultSet rs = pstmt.executeQuery();

                int deleteCount = 0;
                while (rs.next()) {
                    String filename = rs.getString("filename");
                    Path filePath = Paths.get(HttpFileServer.RECYCLE_DIR + java.io.File.separator + filename);
                    if (Files.exists(filePath)) {
                        Files.delete(filePath);
                        deleteCount++;
                    }
                }

                pstmt = ServerContext.getConnection().prepareStatement(
                        "DELETE FROM files WHERE uploader_id = ? AND is_deleted = 1");
                pstmt.setInt(1, userInfo.userId);
                pstmt.executeUpdate();

                sendSuccessResponse(exchange, Map.of("deletedCount", deleteCount));
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().info("用户清空回收站：" + userInfo.username + "（删除文件数：" + deleteCount + "）");
                }
            } catch (Exception e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("清空回收站异常：" + e.getMessage());
                }
                sendErrorResponse(exchange, 500, "清空回收站失败：" + e.getMessage());
            } finally {
                dbLock.unlock();
            }
        }
    }
}
