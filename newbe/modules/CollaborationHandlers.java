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
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

/**
 * 协同处理器，提供加入协同、提交变更、拉取变更的基础接口。
 */
public final class CollaborationHandlers {
    private CollaborationHandlers() {
    }

    /**
     * 加入协同会话：POST /api/collab/join
     * Request JSON: {"fileId":123}
     * Response JSON: {"sessionId":"...","version":0}
     */
    public static class JoinHandler extends AbstractTokenHandler {
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
            FileMeta meta = loadFileMeta(fileId);
            if (meta == null) {
                sendErrorResponse(exchange, 404, "文件不存在或无权限");
                return;
            }
            if (meta.isDeleted()) {
                sendErrorResponse(exchange, 400, "文件已删除，无法协同");
                return;
            }

            CollabSession session = findActiveSession(fileId, userInfo.userId);
            if (session == null) {
                session = createSession(fileId, userInfo.userId);
                if (session == null) {
                    sendErrorResponse(exchange, 500, "创建协同会话失败");
                    return;
                }
            }

            Map<String, Object> resp = new HashMap<>();
            resp.put("sessionId", session.sessionId());
            resp.put("version", session.version());
            resp.put("fileId", fileId);
            sendSuccessResponse(exchange, resp);
        }

        private FileMeta loadFileMeta(int fileId) {
            String sql = "SELECT filename, is_deleted, uploader_id FROM files WHERE id = ?";
            try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(sql)) {
                pstmt.setInt(1, fileId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (!rs.next()) {
                        return null;
                    }
                    return new FileMeta(fileId, rs.getInt("uploader_id"), rs.getInt("is_deleted") == 1);
                }
            } catch (SQLException ex) {
                Logger logger = ServerContext.getLogger();
                if (logger != null) {
                    logger.severe("查询文件失败：" + ex.getMessage());
                }
                return null;
            }
        }

        private CollabSession findActiveSession(int fileId, int ownerId) {
            dbLock.lock();
            try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                    "SELECT session_id, version FROM collab_sessions WHERE file_id = ? AND owner_id = ? AND status = 'ACTIVE'")) {
                pstmt.setInt(1, fileId);
                pstmt.setInt(2, ownerId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        return new CollabSession(rs.getString("session_id"), fileId, ownerId, rs.getInt("version"), "ACTIVE");
                    }
                }
            } catch (SQLException ex) {
                Logger logger = ServerContext.getLogger();
                if (logger != null) {
                    logger.severe("查询协同会话失败：" + ex.getMessage());
                }
            } finally {
                dbLock.unlock();
            }
            return null;
        }

        private CollabSession createSession(int fileId, int ownerId) {
            String sessionId = UUID.randomUUID().toString();
            dbLock.lock();
            try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                    "INSERT INTO collab_sessions (session_id, file_id, owner_id, version, status) VALUES (?, ?, ?, 0, 'ACTIVE')")) {
                pstmt.setString(1, sessionId);
                pstmt.setInt(2, fileId);
                pstmt.setInt(3, ownerId);
                pstmt.executeUpdate();
                return new CollabSession(sessionId, fileId, ownerId, 0, "ACTIVE");
            } catch (SQLException ex) {
                Logger logger = ServerContext.getLogger();
                if (logger != null) {
                    logger.severe("插入协同会话失败：" + ex.getMessage());
                }
                return null;
            } finally {
                dbLock.unlock();
            }
        }
    }

    /**
     * push 操作：POST /api/collab/push
     * Request JSON: {"sessionId":"...","version":2,"delta":"..."}
     */
    public static class PushHandler extends AbstractTokenHandler {
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

            if (body == null || !body.has("sessionId") || !body.has("version") || !body.has("delta")) {
                sendErrorResponse(exchange, 400, "缺少参数：sessionId/version/delta");
                return;
            }

            String sessionId = body.get("sessionId").getAsString();
            int clientVersion = body.get("version").getAsInt();
            String delta = body.get("delta").getAsString();

            CollabSession session = loadSession(sessionId);
            if (session == null) {
                sendErrorResponse(exchange, 404, "协同会话不存在");
                return;
            }
            if (session.ownerId() != userInfo.userId && !userInfo.isAdmin()) {
                sendErrorResponse(exchange, 403, "无权操作该会话");
                return;
            }
            if (!"ACTIVE".equals(session.status())) {
                sendErrorResponse(exchange, 400, "协同会话状态异常");
                return;
            }
            if (clientVersion != session.version()) {
                sendErrorResponse(exchange, 409, "版本冲突，请先拉取最新版本");
                return;
            }

            int newVersion = session.version() + 1;
            dbLock.lock();
            try (PreparedStatement insertEvent = ServerContext.getConnection().prepareStatement(
                    "INSERT INTO collab_events (session_id, user_id, version, delta, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)");
                 PreparedStatement updateSession = ServerContext.getConnection().prepareStatement(
                    "UPDATE collab_sessions SET version = ?, updated_at = CURRENT_TIMESTAMP WHERE session_id = ?")) {
                insertEvent.setString(1, sessionId);
                insertEvent.setInt(2, userInfo.userId);
                insertEvent.setInt(3, newVersion);
                insertEvent.setString(4, delta);
                insertEvent.executeUpdate();

                updateSession.setInt(1, newVersion);
                updateSession.setString(2, sessionId);
                updateSession.executeUpdate();
            } catch (SQLException ex) {
                Logger logger = ServerContext.getLogger();
                if (logger != null) {
                    logger.severe("写入协同事件失败：" + ex.getMessage());
                }
                sendErrorResponse(exchange, 500, "写入协同事件失败");
                return;
            } finally {
                dbLock.unlock();
            }

            Map<String, Object> resp = new HashMap<>();
            resp.put("version", newVersion);
            sendSuccessResponse(exchange, resp);
        }

        private CollabSession loadSession(String sessionId) {
            String sql = "SELECT session_id, file_id, owner_id, version, status FROM collab_sessions WHERE session_id = ?";
            try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(sql)) {
                pstmt.setString(1, sessionId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (!rs.next()) {
                        return null;
                    }
                    return new CollabSession(
                        rs.getString("session_id"),
                        rs.getInt("file_id"),
                        rs.getInt("owner_id"),
                        rs.getInt("version"),
                        rs.getString("status"));
                }
            } catch (SQLException ex) {
                Logger logger = ServerContext.getLogger();
                if (logger != null) {
                    logger.severe("查询协同会话失败：" + ex.getMessage());
                }
                return null;
            }
        }
    }

    /**
     * poll 操作：GET /api/collab/poll?sessionId=xxx&afterVersion=1
     */
    public static class PollHandler extends AbstractTokenHandler {
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持GET方法");
                return;
            }

            Map<String, String> params = FileHelper.parseQueryParams(exchange.getRequestURI().getQuery());
            String sessionId = params.get("sessionId");
            String afterVersionStr = params.get("afterVersion");

            if (sessionId == null || afterVersionStr == null) {
                sendErrorResponse(exchange, 400, "缺少参数：sessionId/afterVersion");
                return;
            }

            int afterVersion;
            try {
                afterVersion = Integer.parseInt(afterVersionStr);
            } catch (NumberFormatException ex) {
                sendErrorResponse(exchange, 400, "afterVersion 必须为数字");
                return;
            }

            CollabSession session = loadSession(sessionId);
            if (session == null) {
                sendErrorResponse(exchange, 404, "协同会话不存在");
                return;
            }
            if (session.ownerId() != userInfo.userId && !userInfo.isAdmin()) {
                sendErrorResponse(exchange, 403, "无权访问该会话");
                return;
            }

            JsonArray events = new JsonArray();
            dbLock.lock();
            try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                    "SELECT version, user_id, delta, created_at FROM collab_events WHERE session_id = ? AND version > ? ORDER BY version ASC")) {
                pstmt.setString(1, sessionId);
                pstmt.setInt(2, afterVersion);
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        JsonObject obj = new JsonObject();
                        obj.addProperty("version", rs.getInt("version"));
                        obj.addProperty("userId", rs.getInt("user_id"));
                        obj.addProperty("delta", rs.getString("delta"));
                        obj.addProperty("createdAt", rs.getString("created_at"));
                        events.add(obj);
                    }
                }
            } catch (SQLException ex) {
                Logger logger = ServerContext.getLogger();
                if (logger != null) {
                    logger.severe("查询协同事件失败：" + ex.getMessage());
                }
                sendErrorResponse(exchange, 500, "查询协同事件失败");
                return;
            } finally {
                dbLock.unlock();
            }

            Map<String, Object> resp = new HashMap<>();
            resp.put("events", events);
            resp.put("currentVersion", session.version());
            sendSuccessResponse(exchange, resp);
        }

        private CollabSession loadSession(String sessionId) {
            String sql = "SELECT session_id, file_id, owner_id, version, status FROM collab_sessions WHERE session_id = ?";
            try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(sql)) {
                pstmt.setString(1, sessionId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (!rs.next()) {
                        return null;
                    }
                    return new CollabSession(
                        rs.getString("session_id"),
                        rs.getInt("file_id"),
                        rs.getInt("owner_id"),
                        rs.getInt("version"),
                        rs.getString("status"));
                }
            } catch (SQLException ex) {
                Logger logger = ServerContext.getLogger();
                if (logger != null) {
                    logger.severe("查询协同会话失败：" + ex.getMessage());
                }
                return null;
            }
        }
    }

    private record FileMeta(int fileId, int uploaderId, boolean deleted) {
        boolean isDeleted() {
            return deleted;
        }
    }

    private record CollabSession(String sessionId, int fileId, int ownerId, int version, String status) {
    }
}