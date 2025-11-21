import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 管理员相关 Handler。
 */
public final class AdminHandlers {
    private AdminHandlers() {}

    public static class AdminDeleteUserHandler extends AbstractTokenHandler {
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!userInfo.isAdmin) {
                sendErrorResponse(exchange, 403, "无管理员权限，禁止操作");
                return;
            }

            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                JsonObject req = gson.fromJson(br, JsonObject.class);
                if (!req.has("username")) {
                    sendErrorResponse(exchange, 400, "缺少参数：username");
                    return;
                }
                String targetUsername = req.get("username").getAsString().trim();

                if ("admin".equals(targetUsername)) {
                    sendErrorResponse(exchange, 400, "禁止删除管理员账户");
                    return;
                }
                if (targetUsername.equals(userInfo.username)) {
                    sendErrorResponse(exchange, 400, "禁止删除当前登录账户");
                    return;
                }

                dbLock.lock();
                try {
                    int targetUserId;
                    try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                            "SELECT id FROM users WHERE username = ?")) {
                        pstmt.setString(1, targetUsername);
                        ResultSet rs = pstmt.executeQuery();
                        if (!rs.next()) {
                            sendErrorResponse(exchange, 404, "待删除用户不存在");
                            return;
                        }
                        targetUserId = rs.getInt("id");
                    }

                    deleteUserFiles(targetUserId);

                    try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                            "DELETE FROM users WHERE id = ?")) {
                        pstmt.setInt(1, targetUserId);
                        int affectedRows = pstmt.executeUpdate();
                        if (affectedRows > 0) {
                            sendSuccessResponse(exchange, null);
                            if (ServerContext.getLogger() != null) {
                                ServerContext.getLogger().info("管理员删除用户成功：" + targetUsername + "（操作人：" + userInfo.username + "）");
                            }
                        } else {
                            sendErrorResponse(exchange, 500, "用户删除失败");
                        }
                    }
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("删除用户异常：" + e.getMessage());
                }
                sendErrorResponse(exchange, 500, "服务器内部错误");
            }
        }

        private void deleteUserFiles(int userId) throws SQLException, IOException {
            List<String> filePaths = new ArrayList<>();
            try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                    "SELECT filepath FROM files WHERE uploader_id = ?")) {
                pstmt.setInt(1, userId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        filePaths.add(rs.getString("filepath"));
                    }
                }
            }

            for (String filePath : filePaths) {
                Path path = Paths.get(filePath);
                if (Files.exists(path)) {
                    Files.delete(path);
                    if (ServerContext.getLogger() != null) {
                        ServerContext.getLogger().info("删除用户文件：" + filePath);
                    }
                }
                Path recyclePath = Paths.get(HttpFileServer.RECYCLE_DIR + java.io.File.separator + path.getFileName());
                if (Files.exists(recyclePath)) {
                    Files.delete(recyclePath);
                    if (ServerContext.getLogger() != null) {
                        ServerContext.getLogger().info("删除回收站文件：" + recyclePath);
                    }
                }
            }

            try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                    "DELETE FROM files WHERE uploader_id = ?")) {
                pstmt.setInt(1, userId);
                pstmt.executeUpdate();
            }
        }
    }
}
