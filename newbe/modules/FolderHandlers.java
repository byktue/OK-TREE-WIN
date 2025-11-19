import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 文件夹管理 Handler。
 */
public final class FolderHandlers {
    private FolderHandlers() {}

    public static class CreateFolderHandler extends AbstractTokenHandler {
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }
            try (BufferedReader br = new BufferedReader(new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                JsonObject req = gson.fromJson(br, JsonObject.class);
                if (req == null || !req.has("folderName")) {
                    sendErrorResponse(exchange, 400, "缺少参数：folderName");
                    return;
                }
                String folderName = req.get("folderName").getAsString().trim();
                Integer parentId = null;
                if (req.has("parentId") && !req.get("parentId").isJsonNull()) {
                    try {
                        parentId = req.get("parentId").getAsInt();
                    } catch (NumberFormatException ex) {
                        sendErrorResponse(exchange, 400, "parentId 必须是数字");
                        return;
                    }
                }

                if (!FileHelper.isValidFilename(folderName)) {
                    sendErrorResponse(exchange, 400, "文件夹名不合法");
                    return;
                }

                FolderService.FolderInfo parentFolder = null;
                if (parentId != null) {
                    try {
                        parentFolder = FolderService.getFolderInfo(parentId, userInfo.userId);
                    } catch (SQLException ex) {
                        if (ServerContext.getLogger() != null) {
                            ServerContext.getLogger().severe("查询上级文件夹失败：" + ex.getMessage());
                        }
                        sendErrorResponse(exchange, 500, "查询上级文件夹失败");
                        return;
                    }
                    if (parentFolder == null) {
                        sendErrorResponse(exchange, 404, "上级文件夹不存在或无权限");
                        return;
                    }
                }

                dbLock.lock();
                try {
                    String duplicateSql = "SELECT COUNT(*) FROM files WHERE uploader_id = ? AND filename = ? AND is_deleted = 0 " +
                        "AND file_type = 'folder' AND " + (parentId == null ? "parent_id IS NULL" : "parent_id = ?");
                    try (PreparedStatement checkStmt = ServerContext.getConnection().prepareStatement(duplicateSql)) {
                        checkStmt.setInt(1, userInfo.userId);
                        checkStmt.setString(2, folderName);
                        if (parentId != null) {
                            checkStmt.setInt(3, parentId);
                        }
                        ResultSet rs = checkStmt.executeQuery();
                        if (rs.next() && rs.getInt(1) > 0) {
                            sendErrorResponse(exchange, 409, "同名文件夹已存在");
                            return;
                        }
                    }

                    String fakePath = "folder://" + System.currentTimeMillis() + "_" + UUID.randomUUID();
                    try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                        "INSERT INTO files (filename, file_type, filepath, filesize, md5, uploader_id, parent_id) VALUES (?, 'folder', ?, 0, '', ?, ?)",
                        Statement.RETURN_GENERATED_KEYS)) {
                        pstmt.setString(1, folderName);
                        pstmt.setString(2, fakePath);
                        pstmt.setInt(3, userInfo.userId);
                        if (parentId == null) {
                            pstmt.setNull(4, Types.INTEGER);
                        } else {
                            pstmt.setInt(4, parentId);
                        }
                        int affected = pstmt.executeUpdate();
                        int newId = -1;
                        try (ResultSet generatedKeys = pstmt.getGeneratedKeys()) {
                            if (generatedKeys.next()) {
                                newId = generatedKeys.getInt(1);
                            }
                        }
                        Map<String, Object> resp = new HashMap<>();
                        resp.put("created", affected);
                        Map<String, Object> folderInfo = new HashMap<>();
                        folderInfo.put("id", newId);
                        folderInfo.put("name", folderName);
                        folderInfo.put("parentId", parentId);
                        resp.put("folder", folderInfo);
                        sendSuccessResponse(exchange, resp);
                        if (ServerContext.getLogger() != null) {
                            ServerContext.getLogger().info("新建文件夹：" + folderName + " 用户=" + userInfo.username);
                        }
                        return;
                    }
                } catch (SQLException e) {
                    if (ServerContext.getLogger() != null) {
                        ServerContext.getLogger().severe("新建文件夹异常：" + e.getMessage());
                    }
                    sendErrorResponse(exchange, 500, "新建文件夹失败：" + e.getMessage());
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("新建文件夹接口异常：" + e.getMessage());
                }
                sendErrorResponse(exchange, 500, "服务器内部错误");
            }
        }
    }
}
