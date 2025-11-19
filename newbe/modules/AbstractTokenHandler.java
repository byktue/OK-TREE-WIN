import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * 带 Token 校验的基础 Handler。
 */
public abstract class AbstractTokenHandler implements HttpHandler {
    protected UserTokenInfo userInfo;
    protected final Gson gson = ServerContext.getGson();

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        setCorsHeaders(exchange);
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, 0);
            exchange.close();
            return;
        }

        try {
            String token = extractToken(exchange);
            if (token == null) {
                sendErrorResponse(exchange, 401, "未提供Token（格式：Authorization: Bearer <token>）");
                return;
            }

            userInfo = SecurityUtils.parseToken(token);
            if (userInfo == null) {
                sendErrorResponse(exchange, 401, "Token无效或已过期");
                return;
            }

            handleWithAuth(exchange);
        } catch (Exception e) {
            if (ServerContext.getLogger() != null) {
                ServerContext.getLogger().severe("接口处理异常：" + e.getMessage());
            }
            sendErrorResponse(exchange, 500, "服务器内部错误");
        } finally {
            if (exchange.getResponseBody() != null) {
                exchange.getResponseBody().close();
            }
        }
    }

    private String extractToken(HttpExchange exchange) {
        String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7).trim();
        }
        return null;
    }

    private void setCorsHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Authorization, Content-Type");
        exchange.getResponseHeaders().set("Access-Control-Max-Age", "86400");
    }

    protected abstract void handleWithAuth(HttpExchange exchange) throws IOException;

    protected void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("code", statusCode);
        response.put("message", message);
        sendResponse(exchange, statusCode, response);
    }

    protected void sendSuccessResponse(HttpExchange exchange, Object data) throws IOException {
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("code", 200);
        response.put("message", "操作成功");
        response.put("data", data);
        sendResponse(exchange, 200, response);
    }

    protected void sendResponse(HttpExchange exchange, int statusCode, Object response) throws IOException {
        String json = gson.toJson(response);
        byte[] responseBytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
}
