import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

/**
 * 文件共享处理器，负责生成分享链接、列出分享记录以及验证访问。
 */
public final class FileShareHandlers {
    private FileShareHandlers() {
    }

    /**
     * 创建分享：POST /api/share/create
     * Request JSON: {"fileId":123,"expireHours":72,"permissions":"read"}
     */
    public static class CreateShareHandler extends AbstractTokenHandler {
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            JsonObject body;
            try (InputStream in = exchange.getRequestBody()) {
                body = ServerContext.getGson().fromJson(new String(in.readAllBytes(), StandardCharsets.UTF_8), JsonObject.class);
            } catch (Exception ex) {
                sendErrorResponse(exchange, 400, "请求体解析失败");
                return;
            }

            if (body == null || !body.has("fileId")) {
                sendErrorResponse(exchange, 400, "缺少参数：fileId");
                return;
            }

            int fileId = body.get("fileId").getAsInt();
            int expireHours = body.has("expireHours") ? Math.max(body.get("expireHours").getAsInt(), 1) : 72;
            String permissions = body.has("permissions") ? body.get("permissions").getAsString() : "read";

            FileMeta fileMeta = loadFileMeta(fileId);
            if (fileMeta == null) {
                sendErrorResponse(exchange, 404, "文件不存在或无权限");
                return;
            }
            if (fileMeta.isDeleted()) {
                sendErrorResponse(exchange, 400, "文件已在回收站，无法分享");
                return;
            }

            String shareId = UUID.randomUUID().toString();
            String token = generateToken();

            dbLock.lock();
            try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                    "INSERT INTO file_shares (share_id, file_id, owner_id, token, permissions, expire_at) " +
                        "VALUES (?, ?, ?, ?, ?, datetime('now', ?))")) {
                pstmt.setString(1, shareId);
                pstmt.setInt(2, fileId);
                pstmt.setInt(3, userInfo.userId);
                pstmt.setString(4, token);
                pstmt.setString(5, permissions);
                pstmt.setString(6, "+" + expireHours + " hours");
                pstmt.executeUpdate();
            } catch (SQLException ex) {
                Logger logger = ServerContext.getLogger();
                if (logger != null) {
                    logger.severe("创建分享失败：" + ex.getMessage());
                }
                sendErrorResponse(exchange, 500, "创建分享失败");
                return;
            } finally {
                dbLock.unlock();
            }

            Map<String, Object> resp = new HashMap<>();
            resp.put("shareId", shareId);
            resp.put("token", token);
            resp.put("expireHours", expireHours);
            resp.put("fileId", fileId);
            resp.put("permissions", permissions);
            sendSuccessResponse(exchange, resp);
        }

        private FileMeta loadFileMeta(int fileId) {
            String sql = "SELECT filename, filepath, is_deleted FROM files WHERE id = ? AND uploader_id = ?";
            try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(sql)) {
                pstmt.setInt(1, fileId);
                pstmt.setInt(2, userInfo.userId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (!rs.next()) {
                        return null;
                    }
                    return new FileMeta(fileId, rs.getString("filename"), rs.getString("filepath"), rs.getInt("is_deleted") == 1);
                }
            } catch (SQLException ex) {
                Logger logger = ServerContext.getLogger();
                if (logger != null) {
                    logger.severe("查询文件失败：" + ex.getMessage());
                }
                return null;
            }
        }
    }

    /**
     * 列出分享：GET /api/share/list
     */
    public static class ListShareHandler extends AbstractTokenHandler {
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持GET方法");
                return;
            }

            JsonArray data = new JsonArray();
            dbLock.lock();
            try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                    "SELECT s.share_id, s.file_id, s.token, s.permissions, s.expire_at, s.created_at, " +
                        "f.filename, f.filesize, f.file_type " +
                        "FROM file_shares s LEFT JOIN files f ON s.file_id = f.id " +
                        "WHERE s.owner_id = ? ORDER BY s.created_at DESC")) {
                pstmt.setInt(1, userInfo.userId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        JsonObject obj = new JsonObject();
                        obj.addProperty("shareId", rs.getString("share_id"));
                        obj.addProperty("fileId", rs.getInt("file_id"));
                        obj.addProperty("token", rs.getString("token"));
                        obj.addProperty("permissions", rs.getString("permissions"));
                        obj.addProperty("expireAt", rs.getString("expire_at"));
                        obj.addProperty("createdAt", rs.getString("created_at"));
                        obj.addProperty("fileName", rs.getString("filename"));
                        obj.addProperty("fileSize", rs.getLong("filesize"));
                        obj.addProperty("fileType", rs.getString("file_type"));
                        data.add(obj);
                    }
                }
            } catch (SQLException ex) {
                Logger logger = ServerContext.getLogger();
                if (logger != null) {
                    logger.severe("查询分享列表失败：" + ex.getMessage());
                }
                sendErrorResponse(exchange, 500, "查询分享列表失败");
                return;
            } finally {
                dbLock.unlock();
            }

            Map<String, Object> resp = new HashMap<>();
            resp.put("shares", data);
            sendSuccessResponse(exchange, resp);
        }
    }

    /**
     * 访问分享：GET /api/share/access?token=xxx
     * 若只需验证与返回文件信息，可直接返回 JSON；如需下载，可重用 FileDownloadHandler。
     */
    public static class AccessShareHandler extends AbstractTokenHandler {
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持GET方法");
                return;
            }

            String token = exchange.getRequestHeaders().getFirst("X-Share-Token");
            if (token == null || token.isBlank()) {
                sendErrorResponse(exchange, 400, "缺少分享令牌(X-Share-Token)");
                return;
            }

            ShareRecord record = fetchShareByToken(token);
            if (record == null) {
                sendErrorResponse(exchange, 404, "分享不存在或已过期");
                return;
            }

            if (!record.ownerId().equals(userInfo.userId) && !userInfo.isAdmin()) {
                sendErrorResponse(exchange, 403, "无权访问该分享");
                return;
            }

            Map<String, Object> data = new HashMap<>();
            data.put("fileId", record.fileId());
            data.put("shareId", record.shareId());
            data.put("permissions", record.permissions());
            data.put("expireAt", record.expireAt());
            data.put("fileName", record.fileName());

            sendSuccessResponse(exchange, data);
        }

        private ShareRecord fetchShareByToken(String token) {
            String sql = "SELECT s.share_id, s.file_id, s.owner_id, s.permissions, s.expire_at, f.filename, f.is_deleted " +
                "FROM file_shares s JOIN files f ON s.file_id = f.id " +
                "WHERE s.token = ? AND (s.expire_at IS NULL OR datetime(s.expire_at) > datetime('now'))";

            dbLock.lock();
            try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(sql)) {
                pstmt.setString(1, token);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (!rs.next()) {
                        return null;
                    }
                    if (rs.getInt("is_deleted") == 1) {
                        return null;
                    }
                    return new ShareRecord(
                        rs.getString("share_id"),
                        rs.getInt("file_id"),
                        rs.getInt("owner_id"),
                        rs.getString("permissions"),
                        rs.getString("expire_at"),
                        rs.getString("filename"));
                }
            } catch (SQLException ex) {
                Logger logger = ServerContext.getLogger();
                if (logger != null) {
                    logger.severe("查询分享失败：" + ex.getMessage());
                }
                return null;
            } finally {
                dbLock.unlock();
            }
        }
    }

    private static String generateToken() {
        String alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        StringBuilder sb = new StringBuilder(12);
        ThreadLocalRandom random = ThreadLocalRandom.current();
        for (int i = 0; i < 12; i++) {
            sb.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return sb.toString();
    }

    private record FileMeta(int id, String name, String path, boolean deleted) {
        boolean isDeleted() {
            return deleted;
        }
    }

    private record ShareRecord(String shareId, Integer fileId, Integer ownerId, String permissions, String expireAt, String fileName) {
    }
}