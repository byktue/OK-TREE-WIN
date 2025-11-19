import com.google.gson.Gson;
import java.sql.Connection;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

/**
 * 全局上下文，集中管理数据库连接、Gson 实例和日志器等共享资源。
 */
public final class ServerContext {
    private static Connection connection;
    private static Gson gson;
    private static Logger logger;
    private static ReentrantLock dbLock;

    private ServerContext() {
    }

    public static void initialize(Connection conn, Gson gsonInstance, Logger log, ReentrantLock lock) {
        connection = conn;
        gson = gsonInstance;
        logger = log;
        dbLock = lock;
    }

    public static Connection getConnection() {
        return connection;
    }

    public static Gson getGson() {
        return gson;
    }

    public static Logger getLogger() {
        return logger;
    }

    public static ReentrantLock getDbLock() {
        return dbLock;
    }
}
