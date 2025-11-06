import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.time.LocalDateTime;

// 日志装饰器：包装所有Handler，添加连接事件打印
public class LoggingHandler implements HttpHandler {
    private final HttpHandler originalHandler; // 被包装的原始Handler

    // 构造方法：传入原始Handler
    public LoggingHandler(HttpHandler originalHandler) {
        this.originalHandler = originalHandler;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // 1. 打印连接事件（在处理请求前执行）
        String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();
        LocalDateTime time = LocalDateTime.now();

        System.out.printf(
            "[%s] 新的HTTP连接 - IP: %s, 方法: %s, 路径: %s%n",
            time, clientIp, method, path
        );

        // 2. 调用原始Handler的处理逻辑（不改变原有功能）
        originalHandler.handle(exchange);
    }
}