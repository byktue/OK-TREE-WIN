import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 登录与注册相关 Handler。
 */
public final class AuthHandlers {
    private AuthHandlers() {}

    public static class LoginHandler implements HttpHandler {
        private final Gson gson = ServerContext.getGson();
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            setCorsHeaders(exchange);
            if ("OPTIONS".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, 0);
                exchange.close();
                return;
            }

            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                JsonObject req = gson.fromJson(br, JsonObject.class);
                if (!req.has("username") || !req.has("password")) {
                    sendErrorResponse(exchange, 400, "缺少参数：username或password");
                    return;
                }
                String username = req.get("username").getAsString().trim();
                String password = req.get("password").getAsString().trim();

                dbLock.lock();
                try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                        "SELECT id, password, salt, is_admin, is_member FROM users WHERE username = ?")) {
                    pstmt.setString(1, username);
                    ResultSet rs = pstmt.executeQuery();

                    if (rs.next()) {
                        String storedPwd = rs.getString("password");
                        String salt = rs.getString("salt");
                        if (!SecurityUtils.verifyPassword(password, storedPwd, salt)) {
                            sendErrorResponse(exchange, 401, "用户名或密码错误");
                            return;
                        }

                        String token = SecurityUtils.generateToken(
                                rs.getInt("id"),
                                username,
                                rs.getInt("is_admin") == 1,
                                rs.getInt("is_member") == 1
                        );

                        Map<String, Object> userData = new HashMap<>();
                        userData.put("id", rs.getInt("id"));
                        userData.put("username", username);
                        userData.put("isAdmin", rs.getInt("is_admin") == 1);
                        userData.put("isMember", rs.getInt("is_member") == 1);

                        Map<String, Object> response = new HashMap<>();
                        response.put("success", true);
                        response.put("code", 200);
                        response.put("message", "登录成功");
                        response.put("token", token);
                        Map<String, Object> dataWrapper = new HashMap<>();
                        dataWrapper.put("token", token);
                        dataWrapper.put("user", userData);
                        response.put("data", dataWrapper);
                        sendResponse(exchange, 200, response);
                        if (ServerContext.getLogger() != null) {
                            ServerContext.getLogger().info("用户登录成功：" + username);
                        }
                    } else {
                        sendErrorResponse(exchange, 401, "用户名或密码错误");
                        if (ServerContext.getLogger() != null) {
                            ServerContext.getLogger().warning("登录失败：用户名不存在 - " + username);
                        }
                    }
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("登录接口异常：" + e.getMessage());
                }
                sendErrorResponse(exchange, 500, "服务器内部错误");
            }
        }

        private void setCorsHeaders(HttpExchange exchange) {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With, Authorization");
            exchange.getResponseHeaders().set("Access-Control-Max-Age", "86400");
        }

        private void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("code", statusCode);
            response.put("message", message);
            sendResponse(exchange, statusCode, response);
        }

        private void sendResponse(HttpExchange exchange, int statusCode, Object response) throws IOException {
            String json = gson.toJson(response);
            byte[] responseBytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
            exchange.sendResponseHeaders(statusCode, responseBytes.length);
            try (var os = exchange.getResponseBody()) {
                os.write(responseBytes);
            }
        }
    }

    public static class RegisterHandler implements HttpHandler {
        private final Gson gson = ServerContext.getGson();
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            setCorsHeaders(exchange);
            if ("OPTIONS".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, 0);
                exchange.close();
                return;
            }

            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                JsonObject req = gson.fromJson(br, JsonObject.class);
                if (!req.has("username") || !req.has("password")) {
                    sendErrorResponse(exchange, 400, "缺少参数：username或password");
                    return;
                }

                String username = req.get("username").getAsString().trim();
                String password = req.get("password").getAsString().trim();

                if (username.length() < 3 || username.length() > 20) {
                    sendErrorResponse(exchange, 400, "用户名长度需3-20位");
                    return;
                }
                if (password.length() < 6 || password.length() > 20) {
                    sendErrorResponse(exchange, 400, "密码长度需6-20位");
                    return;
                }
                if (!username.matches("^[a-zA-Z0-9_]+$")) {
                    sendErrorResponse(exchange, 400, "用户名只允许字母、数字、下划线");
                    return;
                }

                dbLock.lock();
                try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                        "INSERT INTO users (username, password, salt) VALUES (?, ?, ?)")) {
                    String salt = SecurityUtils.generateSalt();
                    String encryptedPwd = SecurityUtils.encryptPassword(password, salt);
                    pstmt.setString(1, username);
                    pstmt.setString(2, encryptedPwd);
                    pstmt.setString(3, salt);
                    pstmt.executeUpdate();

                    Map<String, Object> response = new HashMap<>();
                    response.put("success", true);
                    response.put("code", 200);
                    response.put("message", "注册成功，请登录");
                    sendResponse(exchange, 200, response);
                    if (ServerContext.getLogger() != null) {
                        ServerContext.getLogger().info("用户注册成功：" + username);
                    }
                } catch (SQLException e) {
                    sendErrorResponse(exchange, 400, "用户名已存在");
                    if (ServerContext.getLogger() != null) {
                        ServerContext.getLogger().warning("注册失败：用户名重复 - " + username);
                    }
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("注册接口异常：" + e.getMessage());
                }
                sendErrorResponse(exchange, 500, "服务器内部错误");
            }
        }

        private void setCorsHeaders(HttpExchange exchange) {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With, Authorization");
            exchange.getResponseHeaders().set("Access-Control-Max-Age", "86400");
        }

        private void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("code", statusCode);
            response.put("message", message);
            sendResponse(exchange, statusCode, response);
        }

        private void sendResponse(HttpExchange exchange, int statusCode, Object response) throws IOException {
            String json = gson.toJson(response);
            byte[] responseBytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
            exchange.sendResponseHeaders(statusCode, responseBytes.length);
            try (var os = exchange.getResponseBody()) {
                os.write(responseBytes);
            }
        }
    }
}
