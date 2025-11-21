import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.sun.net.httpserver.HttpServer;
import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * HTTP 文件服务器入口类，负责初始化目录、数据库以及路由注册。
 */
public class HttpFileServer {
    public static final int PORT = 3000;
    public static final String DATA_DIR = "data";
    public static final String STORAGE_DIR = DATA_DIR + File.separator + "server_storage";
    public static final String RECYCLE_DIR = DATA_DIR + File.separator + "recycle_bin";
    public static final String UPLOAD_DIR = STORAGE_DIR + File.separator + "uploads";
    public static final String DB_FILE = DATA_DIR + File.separator + "file_server.db";
    public static final long MAX_UPLOAD_SIZE = 50 * 1024 * 1024L;

    private static Connection db;
    private static final ReentrantLock dbLock = new ReentrantLock();
    private static final Gson gson = new GsonBuilder()
        .setPrettyPrinting()
        .setDateFormat("yyyy-MM-dd HH:mm:ss")
        .create();
    private static final Logger logger = Logger.getLogger(HttpFileServer.class.getName());

    static {
        ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setFormatter(new SimpleFormatter() {
            @Override
            public String format(LogRecord record) {
                return String.format("[%s] [%s] %s - %s%n",
                    new Date(record.getMillis()),
                    record.getLevel(),
                    record.getSourceMethodName(),
                    record.getMessage());
            }
        });
        logger.addHandler(consoleHandler);
        logger.setLevel(Level.INFO);
        logger.setUseParentHandlers(false);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("服务器正在关闭，释放资源...");
            try {
                if (db != null && !db.isClosed()) {
                    db.close();
                    logger.info("数据库连接已关闭");
                }
            } catch (SQLException e) {
                logger.severe("关闭数据库连接失败：" + e.getMessage());
            }
            logger.info("服务器已正常关闭");
        }));
    }

    public static void main(String[] args) {
        try {
            initDirectories();
            initDatabase();
            startHttpServer();
            logger.info("HTTP文件服务器已启动，监听端口：" + PORT);
        } catch (IOException e) {
            logger.severe("目录初始化失败：" + e.getMessage());
            System.exit(1);
        } catch (SQLException e) {
            logger.severe("数据库初始化失败：" + e.getMessage());
            System.exit(1);
        }
    }

    private static void initDirectories() throws IOException {
        createDirectoryWithCheck(DATA_DIR);
        createDirectoryWithCheck(STORAGE_DIR);
        createDirectoryWithCheck(UPLOAD_DIR);
        createDirectoryWithCheck(RECYCLE_DIR);
        logger.info("所有工作目录初始化完成");
    }

    private static void createDirectoryWithCheck(String dirPath) throws IOException {
        Path path = Paths.get(dirPath);
        if (!Files.exists(path)) {
            Files.createDirectories(path);
            logger.info("创建目录：" + dirPath);
        }
        if (!Files.isWritable(path) || !Files.isReadable(path)) {
            throw new IOException("目录权限不足：" + dirPath + "（需读写权限）");
        }
    }

    private static void initDatabase() throws SQLException {
    String url = "jdbc:sqlite:" + DB_FILE + "?synchronous=NORMAL&journal_mode=WAL&cache_size=10000";
        db = DriverManager.getConnection(url);
        db.setAutoCommit(true);

        ServerContext.initialize(db, gson, logger, dbLock);

        try (Statement stmt = db.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS users (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "username TEXT UNIQUE NOT NULL, " +
                "password TEXT NOT NULL, " +
                "salt TEXT NOT NULL, " +
                "nickname TEXT DEFAULT '', " +
                "email TEXT, " +
                "is_admin INTEGER DEFAULT 0, " +
                "is_member INTEGER DEFAULT 0, " +
                "created_at DATETIME DEFAULT CURRENT_TIMESTAMP, " +
                "updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)");

            stmt.execute("CREATE TABLE IF NOT EXISTS files (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "filename TEXT NOT NULL, " +
                "file_type TEXT, " +
                "filepath TEXT UNIQUE NOT NULL, " +
                "filesize INTEGER NOT NULL, " +
                "md5 TEXT NOT NULL, " +
                "uploader_id INTEGER NOT NULL, " +
                "parent_id INTEGER, " +
                "upload_time DATETIME DEFAULT CURRENT_TIMESTAMP, " +
                "is_deleted INTEGER DEFAULT 0, " +
                "delete_time DATETIME, " +
                "FOREIGN KEY(uploader_id) REFERENCES users(id) ON DELETE CASCADE, " +
                "FOREIGN KEY(parent_id) REFERENCES files(id) ON DELETE CASCADE)");

            stmt.execute("CREATE TABLE IF NOT EXISTS upload_sessions (" +
                "upload_id TEXT PRIMARY KEY, " +
                "user_id INTEGER NOT NULL, " +
                "file_name TEXT NOT NULL, " +
                "total_size INTEGER NOT NULL, " +
                "uploaded_size INTEGER DEFAULT 0, " +
                "status TEXT DEFAULT 'UPLOADING', " +
                "updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, " +
                "FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)");

            stmt.execute("CREATE TABLE IF NOT EXISTS file_shares (" +
                "share_id TEXT PRIMARY KEY, " +
                "file_id INTEGER NOT NULL, " +
                "owner_id INTEGER NOT NULL, " +
                "token TEXT UNIQUE NOT NULL, " +
                "permissions TEXT DEFAULT 'read', " +
                "expire_at DATETIME, " +
                "created_at DATETIME DEFAULT CURRENT_TIMESTAMP, " +
                "FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE, " +
                "FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE)");

            stmt.execute("CREATE TABLE IF NOT EXISTS collab_sessions (" +
                "session_id TEXT PRIMARY KEY, " +
                "file_id INTEGER NOT NULL, " +
                "owner_id INTEGER NOT NULL, " +
                "version INTEGER DEFAULT 0, " +
                "status TEXT DEFAULT 'ACTIVE', " +
                "updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, " +
                "FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE, " +
                "FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE)");

            stmt.execute("CREATE TABLE IF NOT EXISTS collab_events (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "session_id TEXT NOT NULL, " +
                "user_id INTEGER NOT NULL, " +
                "version INTEGER NOT NULL, " +
                "delta TEXT NOT NULL, " +
                "created_at DATETIME DEFAULT CURRENT_TIMESTAMP, " +
                "FOREIGN KEY(session_id) REFERENCES collab_sessions(session_id) ON DELETE CASCADE, " +
                "FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)");

            ensureFilesParentColumn();

            stmt.execute("CREATE INDEX IF NOT EXISTS idx_uploader_deleted ON files(uploader_id, is_deleted)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_files_parent ON files(parent_id)");

            initDefaultAccounts(stmt);
        }
        logger.info("数据库初始化完成");
    }

    private static void ensureFilesParentColumn() throws SQLException {
        boolean hasParentId = false;
        try (Statement stmt = db.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA table_info(files)")) {
            while (rs.next()) {
                if ("parent_id".equalsIgnoreCase(rs.getString("name"))) {
                    hasParentId = true;
                    break;
                }
            }
        }

        if (!hasParentId) {
            try (Statement alterStmt = db.createStatement()) {
                alterStmt.execute("ALTER TABLE files ADD COLUMN parent_id INTEGER");
                logger.info("旧版本数据表升级：files.parent_id 列已添加");
            }
        }
    }

    private static void initDefaultAccounts(Statement stmt) throws SQLException {
        if (!accountExists(stmt, "admin")) {
            String salt = SecurityUtils.generateSalt();
            String encryptedPwd = SecurityUtils.encryptPassword("admin123", salt);
            stmt.execute(String.format(
                "INSERT INTO users (username, password, salt, is_admin) VALUES ('admin', '%s', '%s', 1)",
                encryptedPwd, salt));
            logger.info("默认管理员账户创建成功：admin/admin123");
        }

        if (!accountExists(stmt, "test")) {
            String salt = SecurityUtils.generateSalt();
            String encryptedPwd = SecurityUtils.encryptPassword("test123", salt);
            stmt.execute(String.format(
                "INSERT INTO users (username, password, salt) VALUES ('test', '%s', '%s')",
                encryptedPwd, salt));
            logger.info("测试账户创建成功：test/test123");
        }
    }

    private static boolean accountExists(Statement stmt, String username) throws SQLException {
        try (ResultSet rs = stmt.executeQuery("SELECT id FROM users WHERE username = '" + username + "'")) {
            return rs.next();
        }
    }

    private static void startHttpServer() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);

        server.createContext("/api/auth/login", new LoggingHandler(new AuthHandlers.LoginHandler()));
        server.createContext("/api/auth/register", new LoggingHandler(new AuthHandlers.RegisterHandler()));

        server.createContext("/api/user/profile", new LoggingHandler(new UserHandlers.UserProfileHandler()));
        server.createContext("/api/user/change-password", new LoggingHandler(new UserHandlers.ChangePasswordHandler()));

        server.createContext("/api/files", new LoggingHandler(new FileHandlers.FileListHandler()));
        server.createContext("/api/files/upload", new LoggingHandler(new FileHandlers.FileUploadHandler()));
        server.createContext("/api/files/delete", new LoggingHandler(new FileHandlers.FileDeleteHandler()));
        server.createContext("/api/files/permanent-delete", new LoggingHandler(new FileHandlers.FilePermanentDeleteHandler()));
        server.createContext("/api/files/create-folder", new LoggingHandler(new FolderHandlers.CreateFolderHandler()));
        server.createContext("/api/files/download", new LoggingHandler(new FileHandlers.FileDownloadHandler()));
    server.createContext("/api/files/content", new LoggingHandler(new FileHandlers.FileContentHandler()));
        server.createContext("/api/files/preview", new LoggingHandler(new FileHandlers.FilePreviewHandler()));

        // 断点续传相关接口
        server.createContext("/api/upload/chunk/start", new LoggingHandler(new BreakpointUploadHandlers.StartHandler()));
        server.createContext("/api/upload/chunk/append", new LoggingHandler(new BreakpointUploadHandlers.AppendHandler()));
        server.createContext("/api/upload/chunk/complete", new LoggingHandler(new BreakpointUploadHandlers.CompleteHandler()));

        // 文件分享接口
        server.createContext("/api/share/create", new LoggingHandler(new FileShareHandlers.CreateShareHandler()));
        server.createContext("/api/share/list", new LoggingHandler(new FileShareHandlers.ListShareHandler()));
        server.createContext("/api/share/access", new LoggingHandler(new FileShareHandlers.AccessShareHandler()));

        // 协同会话接口
        server.createContext("/api/collab/join", new LoggingHandler(new CollaborationHandlers.JoinHandler()));
        server.createContext("/api/collab/push", new LoggingHandler(new CollaborationHandlers.PushHandler()));
        server.createContext("/api/collab/poll", new LoggingHandler(new CollaborationHandlers.PollHandler()));

        server.createContext("/api/recycle-bin", new LoggingHandler(new RecycleHandlers.RecycleBinHandler()));
        server.createContext("/api/recycle-bin/restore", new LoggingHandler(new RecycleHandlers.RestoreHandler()));
        server.createContext("/api/recycle-bin/empty", new LoggingHandler(new RecycleHandlers.EmptyRecycleHandler()));
    server.createContext("/api/storage/usage", new LoggingHandler(new StorageHandlers.UsageHandler()));

        server.createContext("/api/admin/delete-user", new LoggingHandler(new AdminHandlers.AdminDeleteUserHandler()));

        int coreThreads = Runtime.getRuntime().availableProcessors() * 2;
        int maxThreads = Math.max(coreThreads, 20);
        server.setExecutor(new ThreadPoolExecutor(
            coreThreads,
            maxThreads,
            60L,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(100),
            new ThreadPoolExecutor.CallerRunsPolicy()
        ));
        server.start();
    }
}