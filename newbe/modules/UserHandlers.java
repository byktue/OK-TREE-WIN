import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

/**
 * 用户资料与密码相关 Handler。
 */
public final class UserHandlers {
    private UserHandlers() {}

    public static class UserProfileHandler extends AbstractTokenHandler {
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            switch (exchange.getRequestMethod()) {
                case "GET" -> getProfile(exchange);
                case "PUT" -> updateProfile(exchange);
                default -> sendErrorResponse(exchange, 405, "不支持的方法，仅支持GET/PUT");
            }
        }

        private void getProfile(HttpExchange exchange) throws IOException {
            try {
                dbLock.lock();
                try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                        "SELECT username, nickname, email, is_admin, is_member, created_at FROM users WHERE id = ?")) {
                    pstmt.setInt(1, userInfo.userId);
                    ResultSet rs = pstmt.executeQuery();

                    if (rs.next()) {
                        Map<String, Object> profile = new HashMap<>();
                        profile.put("username", rs.getString("username"));
                        profile.put("nickname", rs.getString("nickname") != null ? rs.getString("nickname") : "");
                        profile.put("email", rs.getString("email") != null ? rs.getString("email") : "");
                        profile.put("isAdmin", rs.getInt("is_admin") == 1);
                        profile.put("isMember", rs.getInt("is_member") == 1);
                        profile.put("createdAt", rs.getString("created_at"));
                        sendSuccessResponse(exchange, profile);
                    } else {
                        sendErrorResponse(exchange, 404, "用户不存在");
                    }
                } finally {
                    dbLock.unlock();
                }
            } catch (SQLException e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("获取用户资料异常：" + e.getMessage());
                }
                sendErrorResponse(exchange, 500, "服务器内部错误");
            }
        }

        private void updateProfile(HttpExchange exchange) throws IOException {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                JsonObject req = gson.fromJson(br, JsonObject.class);
                if (!req.has("nickname") || !req.has("email")) {
                    sendErrorResponse(exchange, 400, "缺少参数：nickname或email");
                    return;
                }

                String nickname = req.get("nickname").getAsString().trim();
                String email = req.get("email").getAsString().trim();
                if (!email.isEmpty() && !Pattern.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$", email)) {
                    sendErrorResponse(exchange, 400, "邮箱格式不正确");
                    return;
                }

                dbLock.lock();
                try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                        "UPDATE users SET nickname = ?, email = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")) {
                    pstmt.setString(1, nickname);
                    pstmt.setString(2, email);
                    pstmt.setInt(3, userInfo.userId);
                    int affectedRows = pstmt.executeUpdate();

                    if (affectedRows > 0) {
                        sendSuccessResponse(exchange, null);
                        if (ServerContext.getLogger() != null) {
                            ServerContext.getLogger().info("用户资料更新成功：" + userInfo.username);
                        }
                    } else {
                        sendErrorResponse(exchange, 404, "用户不存在");
                    }
                } finally {
                    dbLock.unlock();
                }
            } catch (SQLException e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("修改用户资料异常：" + e.getMessage());
                }
                sendErrorResponse(exchange, 500, "服务器内部错误");
            }
        }
    }

    public static class ChangePasswordHandler extends AbstractTokenHandler {
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
                if (!req.has("oldPassword") || !req.has("newPassword")) {
                    sendErrorResponse(exchange, 400, "缺少参数：oldPassword或newPassword");
                    return;
                }

                String oldPwd = req.get("oldPassword").getAsString().trim();
                String newPwd = req.get("newPassword").getAsString().trim();
                if (newPwd.length() < 6 || newPwd.length() > 20) {
                    sendErrorResponse(exchange, 400, "新密码长度需6-20位");
                    return;
                }
                if (oldPwd.equals(newPwd)) {
                    sendErrorResponse(exchange, 400, "新密码不能与旧密码相同");
                    return;
                }

                dbLock.lock();
                try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                        "SELECT password, salt FROM users WHERE id = ?")) {
                    pstmt.setInt(1, userInfo.userId);
                    ResultSet rs = pstmt.executeQuery();

                    if (!rs.next()) {
                        sendErrorResponse(exchange, 404, "用户不存在");
                        return;
                    }

                    String storedPwd = rs.getString("password");
                    String salt = rs.getString("salt");
                    if (!SecurityUtils.verifyPassword(oldPwd, storedPwd, salt)) {
                        sendErrorResponse(exchange, 400, "旧密码错误");
                        return;
                    }

                    String newSalt = SecurityUtils.generateSalt();
                    String newEncryptedPwd = SecurityUtils.encryptPassword(newPwd, newSalt);
                    try (PreparedStatement updateStmt = ServerContext.getConnection().prepareStatement(
                            "UPDATE users SET password = ?, salt = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")) {
                        updateStmt.setString(1, newEncryptedPwd);
                        updateStmt.setString(2, newSalt);
                        updateStmt.setInt(3, userInfo.userId);
                        updateStmt.executeUpdate();
                    }

                    sendSuccessResponse(exchange, null);
                    if (ServerContext.getLogger() != null) {
                        ServerContext.getLogger().info("密码修改成功：" + userInfo.username);
                    }
                } finally {
                    dbLock.unlock();
                }
            } catch (SQLException e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("修改密码异常：" + e.getMessage());
                }
                sendErrorResponse(exchange, 500, "服务器内部错误");
            }
        }
    }
}
