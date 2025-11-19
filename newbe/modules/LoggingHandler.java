import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.util.logging.Logger;

/**
 * 统一的请求日志装饰器。
 */
public class LoggingHandler implements HttpHandler {
    private final HttpHandler delegate;

    public LoggingHandler(HttpHandler delegate) {
        this.delegate = delegate;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        Logger logger = ServerContext.getLogger();
        if (logger != null) {
            String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();
            logger.info(String.format("收到请求 - 客户端IP: %s, 方法: %s, 路径: %s",
                clientIp, exchange.getRequestMethod(), exchange.getRequestURI()));
        }
        delegate.handle(exchange);
    }
}