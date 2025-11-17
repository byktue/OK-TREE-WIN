import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;
import com.google.gson.*;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.nio.charset.StandardCharsets;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.util.Date;
import java.util.logging.*;

/**
 * 完善后的HTTP文件服务器
 * 特性：密码加密存储、JWT安全优化、文件大小限制、路径穿越防护、完整异常处理、统一日志、标准化接口响应
 */
public class HttpFileServer {
    // -------------------------- 基础配置（可提取到配置文件） --------------------------
    private static final int PORT = 3000;
    private static final String STORAGE_DIR = "server_storage";
    private static final String RECYCLE_DIR = "recycle_bin";
    private static final String UPLOAD_DIR = STORAGE_DIR + File.separator + "uploads";
    private static final long MAX_UPLOAD_SIZE = 50 * 1024 * 1024; // 最大上传文件50MB
    private static final int SALT_LENGTH = 16; // 密码盐值长度
    private static final int ITERATIONS = 65536; // 密码哈希迭代次数
    private static final int KEY_LENGTH = 256; // 密码哈希密钥长度

    // JWT安全配置（生产环境建议使用环境变量注入）
    private static final String JWT_SECRET = System.getenv("JWT_SECRET") != null ? 
        System.getenv("JWT_SECRET") : "x8V2#zQ9!pL7@wK3$rT5*yB1&mN4%vF6^gH8(jU0)tR2";
    private static final long JWT_EXPIRE = 24 * 60 * 60 * 1000; // 2小时过期（安全最佳实践）
    private static final Key JWT_KEY = Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));

    // 数据库与锁配置
    private static Connection db;
    private static final ReentrantLock dbLock = new ReentrantLock();
    private static final Gson gson = new GsonBuilder()
        .setPrettyPrinting()
        .setDateFormat("yyyy-MM-dd HH:mm:ss") // 统一日期格式
        .create();

    // 日志配置（分级日志，替代System.out）
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
        logger.setUseParentHandlers(false); // 禁用父处理器，避免重复输出
    }

    public static void main(String[] args) {
        try {
            // 初始化目录（含权限检查）
            initDirectories();
            // 初始化数据库（优化连接配置）
            initDatabase();
            // 启动HTTP服务器（优化线程池）
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

    // -------------------------- 初始化方法（职责单一化） --------------------------
    /**
     * 初始化工作目录，检查读写权限
     */
    private static void initDirectories() throws IOException {
        createDirectoryWithCheck(STORAGE_DIR);
        createDirectoryWithCheck(UPLOAD_DIR);
        createDirectoryWithCheck(RECYCLE_DIR);
        logger.info("所有工作目录初始化完成");
    }

    /**
     * 创建目录并验证读写权限
     */
    private static void createDirectoryWithCheck(String dirPath) throws IOException {
        Path path = Paths.get(dirPath);
        if (!Files.exists(path)) {
            Files.createDirectories(path);
            logger.info("创建目录：" + dirPath);
        }
        // 检查目录权限
        if (!Files.isWritable(path) || !Files.isReadable(path)) {
            throw new IOException("目录权限不足：" + dirPath + "（需读写权限）");
        }
    }

    /**
     * 初始化数据库，创建表结构和默认账户
     */
    private static void initDatabase() throws SQLException {
        // SQLite优化配置：WAL模式（提高并发性能）+ 同步模式（防止数据丢失）
        String url = "jdbc:sqlite:file_server.db?synchronous=NORMAL&journal_mode=WAL&cache_size=10000";
        db = DriverManager.getConnection(url);
        db.setAutoCommit(true);

        try (Statement stmt = db.createStatement()) {
        // 用户表：移除 SQLite 不支持的 COMMENT 子句
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
            
        // 文件表：移除 SQLite 不支持的 COMMENT 子句与内联 INDEX，后续单独创建索引
        stmt.execute("CREATE TABLE IF NOT EXISTS files (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "filename TEXT NOT NULL, " +
            "file_type TEXT, " +
            "filepath TEXT UNIQUE NOT NULL, " +
            "filesize INTEGER NOT NULL, " +
            "md5 TEXT NOT NULL, " +
            "uploader_id INTEGER NOT NULL, " +
            "upload_time DATETIME DEFAULT CURRENT_TIMESTAMP, " +
            "is_deleted INTEGER DEFAULT 0, " +
            "delete_time DATETIME, " +
            "FOREIGN KEY(uploader_id) REFERENCES users(id) ON DELETE CASCADE)");

        // 为 files 表创建索引以优化查询（SQLite 单独创建索引）
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_uploader_deleted ON files(uploader_id, is_deleted)");

            // 初始化默认账户（密码加密存储）
            initDefaultAccounts(stmt);
        }
        logger.info("数据库初始化完成");
    }

    /**
     * 初始化管理员和测试账户（密码加密）
     */
    private static void initDefaultAccounts(Statement stmt) throws SQLException {
        // 管理员账户：admin/admin123
        if (!accountExists(stmt, "admin")) {
            String salt = generateSalt();
            String encryptedPwd = encryptPassword("admin123", salt);
            stmt.execute(String.format(
                "INSERT INTO users (username, password, salt, is_admin) VALUES ('admin', '%s', '%s', 1)",
                encryptedPwd, salt));
            logger.info("默认管理员账户创建成功：admin/admin123");
        }

        // 测试账户：test/test123
        if (!accountExists(stmt, "test")) {
            String salt = generateSalt();
            String encryptedPwd = encryptPassword("test123", salt);
            stmt.execute(String.format(
                "INSERT INTO users (username, password, salt) VALUES ('test', '%s', '%s')",
                encryptedPwd, salt));
            logger.info("测试账户创建成功：test/test123");
        }
    }

    /**
     * 检查账户是否已存在
     */
    private static boolean accountExists(Statement stmt, String username) throws SQLException {
        ResultSet rs = stmt.executeQuery("SELECT id FROM users WHERE username = '" + username + "'");
        boolean exists = rs.next();
        rs.close();
        return exists;
    }

    /**
     * 启动HTTP服务器，配置所有接口上下文
     */
    private static void startHttpServer() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        
        // 无需认证的接口
        server.createContext("/api/auth/login", new LoggingHandler(new LoginHandler()));
        server.createContext("/api/auth/register", new LoggingHandler(new RegisterHandler()));
        
        // 需要Token认证的接口
        server.createContext("/api/user/profile", new LoggingHandler(new UserProfileHandler()));
        server.createContext("/api/user/change-password", new LoggingHandler(new ChangePasswordHandler()));
        server.createContext("/api/files", new LoggingHandler(new FileListHandler()));
        server.createContext("/api/files/upload", new LoggingHandler(new FileUploadHandler()));
        server.createContext("/api/files/delete", new LoggingHandler(new FileDeleteHandler()));
    // 永久删除单个文件（前端请求时将文件从回收站中永久移除）
    server.createContext("/api/files/permanent-delete", new LoggingHandler(new FilePermanentDeleteHandler()));
        server.createContext("/api/files/download", new LoggingHandler(new FileDownloadHandler()));
        server.createContext("/api/files/preview", new LoggingHandler(new FilePreviewHandler()));
        server.createContext("/api/recycle-bin", new LoggingHandler(new RecycleBinHandler()));
        server.createContext("/api/recycle-bin/restore", new LoggingHandler(new RestoreHandler()));
        server.createContext("/api/recycle-bin/empty", new LoggingHandler(new EmptyRecycleHandler()));
        server.createContext("/api/admin/delete-user", new LoggingHandler(new AdminDeleteUserHandler()));

        // 线程池优化：基于CPU核心数动态配置，避免资源耗尽
        int coreThreads = Runtime.getRuntime().availableProcessors() * 2;
        server.setExecutor(new ThreadPoolExecutor(
            coreThreads,
            20, // 最大线程数限制
            60L,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(100), // 任务队列大小
            new ThreadPoolExecutor.CallerRunsPolicy() // 队列满时回退到调用线程
        ));
        server.start();
    }

    // -------------------------- 安全工具方法 --------------------------
    /**
     * 生成随机盐值（Base64编码）
     */
    private static String generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * 密码加密（PBKDF2WithHmacSHA256算法，比MD5更安全）
     */
    private static String encryptPassword(String password, String salt) {
        try {
            KeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                Base64.getDecoder().decode(salt),
                ITERATIONS,
                KEY_LENGTH
            );
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.severe("密码加密失败：" + e.getMessage());
            throw new RuntimeException("密码加密异常", e);
        }
    }

    /**
     * 验证密码（输入密码 vs 存储的加密密码）
     */
    private static boolean verifyPassword(String inputPwd, String storedPwd, String salt) {
        String encryptedInput = encryptPassword(inputPwd, salt);
        return encryptedInput.equals(storedPwd);
    }

    /**
     * 校验文件名合法性（防止路径穿越攻击）
     */
    private static boolean isValidFilename(String filename) {
        if (filename == null || filename.isEmpty() || filename.length() > 255) {
            return false;
        }
        // 禁止包含路径分隔符和特殊字符（: * ? " < > | \ / ..）
        Pattern invalidPattern = Pattern.compile("[\\\\/:*?\"<>|]|\\.\\.");
        return !invalidPattern.matcher(filename).find();
    }

    /**
     * 计算文件MD5值（用于文件完整性校验）
     */
    private static String calculateFileMd5(String filePath) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        try (InputStream is = Files.newInputStream(Paths.get(filePath))) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                md.update(buffer, 0, bytesRead);
            }
        }
        byte[] digest = md.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // -------------------------- JWT工具方法 --------------------------
    /**
     * 生成JWT Token（含唯一标识jti，防止重放攻击）
     */
    private static String generateToken(int userId, String username, boolean isAdmin, boolean isMember) {
        return Jwts.builder()
            .setId(UUID.randomUUID().toString()) // 唯一标识
            .setSubject(String.valueOf(userId))
            .claim("username", username)
            .claim("isAdmin", isAdmin)
            .claim("isMember", isMember)
            .setIssuedAt(new Date()) // 签发时间
            .setExpiration(new Date(System.currentTimeMillis() + JWT_EXPIRE))
            .signWith(JWT_KEY, SignatureAlgorithm.HS256)
            .compact();
    }

    /**
     * 解析JWT Token（详细异常日志，便于排查）
     */
    private static UserTokenInfo parseToken(String token) {
        try {
            Claims claims = Jwts.parser()
                .setSigningKey(JWT_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();

            // 双重校验过期时间
            if (claims.getExpiration().before(new Date())) {
                logger.warning("Token已过期：用户ID=" + claims.getSubject());
                return null;
            }

            return new UserTokenInfo(
                Integer.parseInt(claims.getSubject()),
                claims.get("username", String.class),
                claims.get("isAdmin", Boolean.class),
                claims.get("isMember", Boolean.class)
            );
        } catch (ExpiredJwtException e) {
            logger.warning("Token过期：" + e.getMessage());
        } catch (MalformedJwtException e) {
            logger.warning("Token格式错误：" + e.getMessage());
        } catch (io.jsonwebtoken.SignatureException e) {
            logger.warning("Token签名错误：" + e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.warning("Token为空：" + e.getMessage());
        } catch (JwtException e) {
            logger.warning("Token无效：" + e.getMessage());
        }
        return null;
    }

    /**
     * Token解析后的用户信息封装类
     */
    static class UserTokenInfo {
        int userId;
        String username;
        boolean isAdmin;
        boolean isMember;

        UserTokenInfo(int userId, String username, boolean isAdmin, boolean isMember) {
            this.userId = userId;
            this.username = username;
            this.isAdmin = isAdmin;
            this.isMember = isMember;
        }
    }

    // -------------------------- 抽象Token验证Handler（统一认证逻辑） --------------------------
    static abstract class AbstractTokenHandler implements HttpHandler {
        protected UserTokenInfo userInfo;

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // 统一设置CORS头
            setCorsHeaders(exchange);
            
            // 处理OPTIONS预检请求
            if ("OPTIONS".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, 0);
                exchange.close();
                return;
            }

            try {
                // 提取并验证Token
                String token = extractToken(exchange);
                if (token == null) {
                    sendErrorResponse(exchange, 401, "未提供Token（格式：Authorization: Bearer <token>）");
                    return;
                }

                userInfo = parseToken(token);
                if (userInfo == null) {
                    sendErrorResponse(exchange, 401, "Token无效或已过期");
                    return;
                }

                // 认证通过，执行业务逻辑
                handleWithAuth(exchange);
            } catch (Exception e) {
                logger.severe("接口处理异常：" + e.getMessage());
                sendErrorResponse(exchange, 500, "服务器内部错误");
            } finally {
                // 确保响应体关闭
                if (exchange.getResponseBody() != null) {
                    exchange.getResponseBody().close();
                }
            }
        }

        /**
         * 提取Authorization头中的Token
         */
        private String extractToken(HttpExchange exchange) {
            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                return authHeader.substring(7).trim();
            }
            return null;
        }

        /**
         * 设置CORS响应头
         */
        private void setCorsHeaders(HttpExchange exchange) {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Authorization, Content-Type");
            exchange.getResponseHeaders().set("Access-Control-Max-Age", "86400");
        }

        /**
         * 子类实现具体业务逻辑
         */
        protected abstract void handleWithAuth(HttpExchange exchange) throws IOException;

        /**
         * 发送错误响应（统一格式）
         */
        protected void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("code", statusCode);
            response.put("message", message);
            sendResponse(exchange, statusCode, response);
        }

        /**
         * 发送成功响应（统一格式）
         */
        protected void sendSuccessResponse(HttpExchange exchange, Object data) throws IOException {
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("code", 200);
            response.put("message", "操作成功");
            response.put("data", data);
            sendResponse(exchange, 200, response);
        }

        /**
         * 统一响应发送方法
         */
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

    // -------------------------- 日志包装Handler（统一日志记录） --------------------------
    static class LoggingHandler implements HttpHandler {
        private final HttpHandler delegate;

        LoggingHandler(HttpHandler delegate) {
            this.delegate = delegate;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // 记录请求日志
            String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();
            logger.info(String.format("收到请求 - 客户端IP: %s, 方法: %s, 路径: %s",
                clientIp, exchange.getRequestMethod(), exchange.getRequestURI()));
            delegate.handle(exchange);
        }
    }

    // -------------------------- 认证相关接口 --------------------------
    /**
     * 登录接口（POST）
     */
    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // 设置CORS头
            setCorsHeaders(exchange);
            
            // 处理预检请求
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
                // 解析请求体
                JsonObject req = gson.fromJson(br, JsonObject.class);
                
                // 校验参数
                if (!req.has("username") || !req.has("password")) {
                    sendErrorResponse(exchange, 400, "缺少参数：username或password");
                    return;
                }
                
                String username = req.get("username").getAsString().trim();
                String password = req.get("password").getAsString().trim();

                dbLock.lock();
                try (PreparedStatement pstmt = db.prepareStatement(
                        "SELECT id, password, salt, is_admin, is_member FROM users WHERE username = ?")) {
                    pstmt.setString(1, username);
                    ResultSet rs = pstmt.executeQuery();

                    if (rs.next()) {
                        // 验证密码
                        String storedPwd = rs.getString("password");
                        String salt = rs.getString("salt");
                        if (!verifyPassword(password, storedPwd, salt)) {
                            sendErrorResponse(exchange, 401, "用户名或密码错误");
                            return;
                        }

                        // 生成JWT Token
                        String token = generateToken(
                                rs.getInt("id"),
                                username,
                                rs.getInt("is_admin") == 1,
                                rs.getInt("is_member") == 1
                        );

                        // 成功响应
                        Map<String, Object> userData = new HashMap<>();
                        userData.put("id", rs.getInt("id"));
                        userData.put("username", username);
                        userData.put("isAdmin", rs.getInt("is_admin") == 1);
                        userData.put("isMember", rs.getInt("is_member") == 1);

                        Map<String, Object> response = new HashMap<>();
                        response.put("success", true);
                        response.put("code", 200);
                        response.put("message", "登录成功");
                        // 兼容旧客户端同时返回 top-level token
                        response.put("token", token);
                        // 将 token 与 user 一并放入 data 下，前端期望 data.token 和 data.user
                        Map<String, Object> dataWrapper = new HashMap<>();
                        dataWrapper.put("token", token);
                        dataWrapper.put("user", userData);
                        response.put("data", dataWrapper);
                        sendResponse(exchange, 200, response);
                        logger.info("用户登录成功：" + username);
                    } else {
                        sendErrorResponse(exchange, 401, "用户名或密码错误");
                        logger.warning("登录失败：用户名不存在 - " + username);
                    }
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                logger.severe("登录接口异常：" + e.getMessage());
                sendErrorResponse(exchange, 500, "服务器内部错误");
            }
        }

        /**
         * 设置CORS头
         */
        private void setCorsHeaders(HttpExchange exchange) {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With, Authorization");
            exchange.getResponseHeaders().set("Access-Control-Max-Age", "86400");
        }

        /**
         * 发送错误响应
         */
        private void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("code", statusCode);
            response.put("message", message);
            sendResponse(exchange, statusCode, response);
        }

        /**
         * 发送响应
         */
        private void sendResponse(HttpExchange exchange, int statusCode, Object response) throws IOException {
            String json = gson.toJson(response);
            byte[] responseBytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
            exchange.sendResponseHeaders(statusCode, responseBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseBytes);
            }
        }
    }

    /**
     * 注册接口（POST）
     */
    static class RegisterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // 设置CORS头
            setCorsHeaders(exchange);
            
            // 处理预检请求
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
                
                // 校验参数
                if (!req.has("username") || !req.has("password")) {
                    sendErrorResponse(exchange, 400, "缺少参数：username或password");
                    return;
                }
                
                String username = req.get("username").getAsString().trim();
                String password = req.get("password").getAsString().trim();

                // 参数合法性校验
                if (username.length() < 3 || username.length() > 20) {
                    sendErrorResponse(exchange, 400, "用户名长度需3-20位");
                    return;
                }
                if (password.length() < 6 || password.length() > 20) {
                    sendErrorResponse(exchange, 400, "密码长度需6-20位");
                    return;
                }
                // 用户名只允许字母、数字、下划线
                if (!Pattern.matches("^[a-zA-Z0-9_]+$", username)) {
                    sendErrorResponse(exchange, 400, "用户名只允许字母、数字、下划线");
                    return;
                }

                dbLock.lock();
                try (PreparedStatement pstmt = db.prepareStatement(
                        "INSERT INTO users (username, password, salt) VALUES (?, ?, ?)")) {
                    String salt = generateSalt();
                    String encryptedPwd = encryptPassword(password, salt);
                    pstmt.setString(1, username);
                    pstmt.setString(2, encryptedPwd);
                    pstmt.setString(3, salt);
                    pstmt.executeUpdate();

                    Map<String, Object> response = new HashMap<>();
                    response.put("success", true);
                    response.put("code", 200);
                    response.put("message", "注册成功，请登录");
                    sendResponse(exchange, 200, response);
                    logger.info("用户注册成功：" + username);
                } catch (SQLException e) {
                    // 用户名重复（唯一约束冲突）
                    sendErrorResponse(exchange, 400, "用户名已存在");
                    logger.warning("注册失败：用户名重复 - " + username);
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                logger.severe("注册接口异常：" + e.getMessage());
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
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseBytes);
            }
        }
    }

    // -------------------------- 用户相关接口（需Token） --------------------------
    /**
     * 用户资料接口（GET查询 / PUT修改）
     */
    static class UserProfileHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();
            switch (method) {
                case "GET":
                    getProfile(exchange);
                    break;
                case "PUT":
                    updateProfile(exchange);
                    break;
                default:
                    sendErrorResponse(exchange, 405, "不支持的方法，仅支持GET/PUT");
            }
        }

        /**
         * 获取用户资料
         */
        private void getProfile(HttpExchange exchange) throws IOException {
            try {
                dbLock.lock();
                try (PreparedStatement pstmt = db.prepareStatement(
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
                logger.severe("获取用户资料异常：" + e.getMessage());
                sendErrorResponse(exchange, 500, "服务器内部错误");
            }
        }

        /**
         * 修改用户资料
         */
        private void updateProfile(HttpExchange exchange) throws IOException {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                JsonObject req = gson.fromJson(br, JsonObject.class);
                
                // 校验参数
                if (!req.has("nickname") || !req.has("email")) {
                    sendErrorResponse(exchange, 400, "缺少参数：nickname或email");
                    return;
                }
                
                String nickname = req.get("nickname").getAsString().trim();
                String email = req.get("email").getAsString().trim();

                // 邮箱格式校验（简单校验）
                if (!email.isEmpty() && !Pattern.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$", email)) {
                    sendErrorResponse(exchange, 400, "邮箱格式不正确");
                    return;
                }

                dbLock.lock();
                try (PreparedStatement pstmt = db.prepareStatement(
                        "UPDATE users SET nickname = ?, email = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")) {
                    pstmt.setString(1, nickname);
                    pstmt.setString(2, email);
                    pstmt.setInt(3, userInfo.userId);
                    int affectedRows = pstmt.executeUpdate();

                    if (affectedRows > 0) {
                        sendSuccessResponse(exchange, null);
                        logger.info("用户资料更新成功：" + userInfo.username);
                    } else {
                        sendErrorResponse(exchange, 404, "用户不存在");
                    }
                } finally {
                    dbLock.unlock();
                }
            } catch (SQLException e) {
                logger.severe("修改用户资料异常：" + e.getMessage());
                sendErrorResponse(exchange, 500, "服务器内部错误");
            }
        }
    }

    /**
     * 密码修改接口（POST）
     */
    static class ChangePasswordHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                JsonObject req = gson.fromJson(br, JsonObject.class);
                
                // 校验参数
                if (!req.has("oldPassword") || !req.has("newPassword")) {
                    sendErrorResponse(exchange, 400, "缺少参数：oldPassword或newPassword");
                    return;
                }
                
                String oldPwd = req.get("oldPassword").getAsString().trim();
                String newPwd = req.get("newPassword").getAsString().trim();

                // 新密码校验
                if (newPwd.length() < 6 || newPwd.length() > 20) {
                    sendErrorResponse(exchange, 400, "新密码长度需6-20位");
                    return;
                }
                if (oldPwd.equals(newPwd)) {
                    sendErrorResponse(exchange, 400, "新密码不能与旧密码相同");
                    return;
                }

                dbLock.lock();
                try {
                    // 验证旧密码
                    PreparedStatement pstmt = db.prepareStatement(
                            "SELECT password, salt FROM users WHERE id = ?");
                    pstmt.setInt(1, userInfo.userId);
                    ResultSet rs = pstmt.executeQuery();

                    if (!rs.next()) {
                        sendErrorResponse(exchange, 404, "用户不存在");
                        return;
                    }

                    String storedPwd = rs.getString("password");
                    String salt = rs.getString("salt");
                    if (!verifyPassword(oldPwd, storedPwd, salt)) {
                        sendErrorResponse(exchange, 400, "旧密码错误");
                        return;
                    }

                    // 更新新密码（重新生成盐值，更安全）
                    String newSalt = generateSalt();
                    String newEncryptedPwd = encryptPassword(newPwd, newSalt);
                    pstmt = db.prepareStatement(
                            "UPDATE users SET password = ?, salt = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
                    pstmt.setString(1, newEncryptedPwd);
                    pstmt.setString(2, newSalt);
                    pstmt.setInt(3, userInfo.userId);
                    pstmt.executeUpdate();

                    sendSuccessResponse(exchange, null);
                    logger.info("密码修改成功：" + userInfo.username);
                } finally {
                    dbLock.unlock();
                }
            } catch (SQLException e) {
                logger.severe("修改密码异常：" + e.getMessage());
                sendErrorResponse(exchange, 500, "服务器内部错误");
            }
        }
    }

    // -------------------------- 管理员接口（需Token+管理员权限） --------------------------
    /**
     * 管理员删除用户接口（POST）
     */
    static class AdminDeleteUserHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            // 验证管理员权限
            if (!userInfo.isAdmin) {
                sendErrorResponse(exchange, 403, "无管理员权限，禁止操作");
                return;
            }

            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                JsonObject req = gson.fromJson(br, JsonObject.class);
                if (!req.has("username")) {
                    sendErrorResponse(exchange, 400, "缺少参数：username");
                    return;
                }
                String targetUsername = req.get("username").getAsString().trim();

                // 禁止删除管理员账户
                if ("admin".equals(targetUsername)) {
                    sendErrorResponse(exchange, 400, "禁止删除管理员账户");
                    return;
                }

                // 禁止删除当前登录账户
                if (targetUsername.equals(userInfo.username)) {
                    sendErrorResponse(exchange, 400, "禁止删除当前登录账户");
                    return;
                }

                dbLock.lock();
                try {
                    // 查询待删除用户ID
                    PreparedStatement pstmt = db.prepareStatement(
                            "SELECT id FROM users WHERE username = ?");
                    pstmt.setString(1, targetUsername);
                    ResultSet rs = pstmt.executeQuery();

                    if (!rs.next()) {
                        sendErrorResponse(exchange, 404, "待删除用户不存在");
                        return;
                    }
                    int targetUserId = rs.getInt("id");

                    // 删除用户关联文件（上传目录+回收站）
                    deleteUserFiles(targetUserId);

                    // 删除用户记录（级联删除文件表关联记录）
                    pstmt = db.prepareStatement("DELETE FROM users WHERE id = ?");
                    pstmt.setInt(1, targetUserId);
                    int affectedRows = pstmt.executeUpdate();

                    if (affectedRows > 0) {
                        sendSuccessResponse(exchange, null);
                        logger.info("管理员删除用户成功：" + targetUsername + "（操作人：" + userInfo.username + "）");
                    } else {
                        sendErrorResponse(exchange, 500, "用户删除失败");
                    }
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                logger.severe("删除用户异常：" + e.getMessage());
                sendErrorResponse(exchange, 500, "服务器内部错误");
            }
        }

        /**
         * 删除用户关联的所有文件（物理文件+数据库记录）
         */
        private void deleteUserFiles(int userId) throws SQLException, IOException {
            // 查询用户所有文件路径
            List<String> filePaths = new ArrayList<>();
            try (PreparedStatement pstmt = db.prepareStatement(
                    "SELECT filepath FROM files WHERE uploader_id = ?")) {
                pstmt.setInt(1, userId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        filePaths.add(rs.getString("filepath"));
                    }
                }
            }

            // 删除物理文件（上传目录和回收站）
            for (String filePath : filePaths) {
                Path path = Paths.get(filePath);
                if (Files.exists(path)) {
                    Files.delete(path);
                    logger.info("删除用户文件：" + filePath);
                }
                // 检查回收站是否有同名文件
                Path recyclePath = Paths.get(RECYCLE_DIR + File.separator + path.getFileName());
                if (Files.exists(recyclePath)) {
                    Files.delete(recyclePath);
                    logger.info("删除回收站文件：" + recyclePath);
                }
            }

            // 删除数据库文件记录
            try (PreparedStatement pstmt = db.prepareStatement(
                    "DELETE FROM files WHERE uploader_id = ?")) {
                pstmt.setInt(1, userId);
                pstmt.executeUpdate();
            }
        }
    }

    // -------------------------- 文件管理接口（需Token） --------------------------
    /**
     * 文件列表接口（GET）
     */
    static class FileListHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持GET方法");
                return;
            }

            try {
                dbLock.lock();
                PreparedStatement pstmt = db.prepareStatement(
                        "SELECT id, filename, file_type, filesize, upload_time FROM files " +
                        "WHERE uploader_id = ? AND is_deleted = 0 ORDER BY upload_time DESC");
                pstmt.setInt(1, userInfo.userId);
                ResultSet rs = pstmt.executeQuery();

                List<Map<String, Object>> fileList = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> file = new HashMap<>();
                    file.put("id", rs.getInt("id"));
                    file.put("filename", rs.getString("filename"));
                    file.put("fileType", rs.getString("file_type") != null ? rs.getString("file_type") : "application/octet-stream");
                    file.put("fileSize", rs.getLong("filesize"));
                    file.put("uploadTime", rs.getString("upload_time"));
                    fileList.add(file);
                }

                sendSuccessResponse(exchange, fileList);
                logger.info("用户查询文件列表：" + userInfo.username + "（文件数：" + fileList.size() + "）");
            } catch (SQLException e) {
                logger.severe("查询文件列表异常：" + e.getMessage());
                sendErrorResponse(exchange, 500, "服务器内部错误");
            } finally {
                dbLock.unlock();
            }
        }
    }

    /**
     * 文件上传接口（POST，支持multipart/form-data）
     */
    static class FileUploadHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            // 校验Content-Type
            String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            if (contentType == null || !contentType.startsWith("multipart/form-data")) {
                sendErrorResponse(exchange, 400, "无效的请求格式，需为multipart/form-data");
                return;
            }

            // 解析boundary
            String boundary = extractBoundary(contentType);
            if (boundary == null) {
                sendErrorResponse(exchange, 400, "无法解析multipart边界");
                return;
            }

            try {
                // 读取请求体字节流
                byte[] fullBody = readRequestBody(exchange);
                if (fullBody.length == 0) {
                    sendErrorResponse(exchange, 400, "请求体为空");
                    return;
                }

                // 提取文件名和文件内容
                String originalFilename = extractFilename(fullBody, boundary);
                if (!isValidFilename(originalFilename)) {
                    sendErrorResponse(exchange, 400, "文件名不合法（含特殊字符或路径穿越）");
                    return;
                }

                // 提取文件内容
                byte[] fileContent = extractFileContent(fullBody, boundary);
                if (fileContent == null || fileContent.length == 0) {
                    sendErrorResponse(exchange, 400, "文件内容为空");
                    return;
                }

                // 校验文件大小
                if (fileContent.length > MAX_UPLOAD_SIZE) {
                    sendErrorResponse(exchange, 400, "文件过大，最大支持" + MAX_UPLOAD_SIZE / 1024 / 1024 + "MB");
                    return;
                }

                // 生成存储文件名（避免重复）
                String fileExt = originalFilename.contains(".") ? 
                    originalFilename.substring(originalFilename.lastIndexOf(".")) : ".bin";
                String storedFilename = System.currentTimeMillis() + "_" + UUID.randomUUID().toString() + fileExt;
                String storedFilePath = UPLOAD_DIR + File.separator + storedFilename;
                Path filePath = Paths.get(storedFilePath);

                // 写入文件
                Files.write(filePath, fileContent);
                logger.info("文件写入成功：" + storedFilePath + "（大小：" + fileContent.length + "字节）");

                // 计算文件MD5和MIME类型
                String md5 = calculateFileMd5(storedFilePath);
                String mimeType = Files.probeContentType(filePath);
                if (mimeType == null) {
                    mimeType = "application/octet-stream";
                }

                // 保存到数据库
                dbLock.lock();
                try (PreparedStatement pstmt = db.prepareStatement(
                        "INSERT INTO files (filename, file_type, filepath, filesize, md5, uploader_id) " +
                        "VALUES (?, ?, ?, ?, ?, ?)")) {
                    pstmt.setString(1, originalFilename);
                    pstmt.setString(2, mimeType);
                    pstmt.setString(3, storedFilePath);
                    pstmt.setLong(4, fileContent.length);
                    pstmt.setString(5, md5);
                    pstmt.setInt(6, userInfo.userId);
                    pstmt.executeUpdate();

                    // 响应结果
                    Map<String, Object> fileData = new HashMap<>();
                    fileData.put("id", getLastInsertId());
                    fileData.put("originalFilename", originalFilename);
                    fileData.put("storedFilename", storedFilename);
                    fileData.put("fileType", mimeType);
                    fileData.put("fileSize", fileContent.length);
                    fileData.put("md5", md5);
                    fileData.put("uploadTime", new Date());

                    sendSuccessResponse(exchange, fileData);
                    logger.info("用户上传文件成功：" + userInfo.username + "（文件：" + originalFilename + "）");
                } finally {
                    dbLock.unlock();
                }

            } catch (Exception e) {
                logger.severe("文件上传异常：" + e.getMessage());
                sendErrorResponse(exchange, 500, "文件上传失败：" + e.getMessage());
            }
        }

        /**
         * 读取请求体字节流
         */
        private byte[] readRequestBody(HttpExchange exchange) throws IOException {
            try (InputStream in = exchange.getRequestBody();
                 ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
                return out.toByteArray();
            }
        }

        /**
         * 提取multipart boundary
         */
        private String extractBoundary(String contentType) {
            String[] parts = contentType.split(";");
            for (String part : parts) {
                part = part.trim();
                if (part.startsWith("boundary=")) {
                    String boundary = part.substring("boundary=".length()).trim();
                    // 去除可能的引号
                    if (boundary.startsWith("\"") && boundary.endsWith("\"")) {
                        boundary = boundary.substring(1, boundary.length() - 1);
                    }
                    return boundary.isEmpty() ? null : boundary;
                }
            }
            return null;
        }

        /**
         * 提取文件名
         */
        private String extractFilename(byte[] fullBody, String boundary) {
            String bodyStr = new String(fullBody, StandardCharsets.UTF_8);
            String[] lines = bodyStr.split("\r\n");
            String boundaryDelimiter = "--" + boundary;

            for (int i = 0; i < lines.length; i++) {
                if (lines[i].startsWith(boundaryDelimiter) && i < lines.length - 1) {
                    // 查找包含filename的行
                    for (int j = i + 1; j < lines.length; j++) {
                        if (lines[j].contains("filename=")) {
                            String[] parts = lines[j].split("filename=");
                            if (parts.length >= 2) {
                                String filename = parts[1].trim();
                                // 去除引号
                                if (filename.startsWith("\"") && filename.endsWith("\"")) {
                                    filename = filename.substring(1, filename.length() - 1);
                                }
                                return filename;
                            }
                        }
                    }
                }
            }
            return null;
        }

        /**
         * 提取文件内容字节流
         */
        private byte[] extractFileContent(byte[] fullBody, String boundary) {
            String boundaryDelimiter = "--" + boundary;
            String endBoundary = boundaryDelimiter + "--";
            byte[] boundaryBytes = boundaryDelimiter.getBytes(StandardCharsets.UTF_8);
            byte[] endBoundaryBytes = endBoundary.getBytes(StandardCharsets.UTF_8);
            byte[] contentStartMarker = "\r\n\r\n".getBytes(StandardCharsets.UTF_8);

            // 查找内容起始位置
            int startIndex = indexOf(fullBody, contentStartMarker, 0);
            if (startIndex == -1) {
                return null;
            }
            startIndex += contentStartMarker.length;

            // 查找内容结束位置（优先找结束边界，再找普通边界）
            int endIndex = indexOf(fullBody, endBoundaryBytes, startIndex);
            if (endIndex == -1) {
                endIndex = indexOf(fullBody, boundaryBytes, startIndex);
            }
            if (endIndex == -1) {
                endIndex = fullBody.length;
            } else {
                // 去除结束边界前的换行符
                if (endIndex >= 2 && fullBody[endIndex - 2] == '\r' && fullBody[endIndex - 1] == '\n') {
                    endIndex -= 2;
                }
            }

            // 提取内容
            if (startIndex >= endIndex) {
                return null;
            }
            return Arrays.copyOfRange(fullBody, startIndex, endIndex);
        }

        /**
         * 查找字节数组中的目标字节数组位置
         */
        private int indexOf(byte[] source, byte[] target, int start) {
            if (source == null || target == null || source.length < target.length || start < 0) {
                return -1;
            }
            for (int i = start; i <= source.length - target.length; i++) {
                boolean match = true;
                for (int j = 0; j < target.length; j++) {
                    if (source[i + j] != target[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    return i;
                }
            }
            return -1;
        }

        /**
         * 获取最后插入的ID（SQLite专用）
         */
        private int getLastInsertId() throws SQLException {
            try (Statement stmt = db.createStatement()) {
                ResultSet rs = stmt.executeQuery("SELECT last_insert_rowid()");
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    /**
     * 文件删除接口（POST，移至回收站）
     */
    static class FileDeleteHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                JsonObject req = gson.fromJson(br, JsonObject.class);
                
                if (!req.has("fileId")) {
                    sendErrorResponse(exchange, 400, "缺少参数：fileId");
                    return;
                }
                
                int fileId = req.get("fileId").getAsInt();

                dbLock.lock();
                try {
                    // 查询文件信息（验证归属）
                    PreparedStatement pstmt = db.prepareStatement(
                            "SELECT filename, filepath FROM files WHERE id = ? AND uploader_id = ? AND is_deleted = 0");
                    pstmt.setInt(1, fileId);
                    pstmt.setInt(2, userInfo.userId);
                    ResultSet rs = pstmt.executeQuery();

                    if (!rs.next()) {
                        sendErrorResponse(exchange, 404, "文件不存在或无权限");
                        return;
                    }
                    String filename = rs.getString("filename");
                    String filepath = rs.getString("filepath");

                    // 移动文件到回收站
                    Path sourcePath = Paths.get(filepath);
                    Path targetPath = Paths.get(RECYCLE_DIR + File.separator + filename);
                    // 若回收站已有同名文件，添加时间戳后缀
                    if (Files.exists(targetPath)) {
                        String timestamp = String.valueOf(System.currentTimeMillis());
                        String newFilename = timestamp + "_" + filename;
                        targetPath = Paths.get(RECYCLE_DIR + File.separator + newFilename);
                    }
                    Files.move(sourcePath, targetPath, StandardCopyOption.REPLACE_EXISTING);

                    // 更新数据库状态
                    pstmt = db.prepareStatement(
                            "UPDATE files SET is_deleted = 1, delete_time = CURRENT_TIMESTAMP WHERE id = ?");
                    pstmt.setInt(1, fileId);
                    pstmt.executeUpdate();

                    sendSuccessResponse(exchange, null);
                    logger.info("用户删除文件（移至回收站）：" + userInfo.username + "（文件：" + filename + "）");
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                logger.severe("删除文件异常：" + e.getMessage());
                sendErrorResponse(exchange, 500, "文件删除失败：" + e.getMessage());
            }
        }
    }

    /**
     * 单文件永久删除接口（POST）
     * 说明：仅允许删除属于当前用户且已在回收站（is_deleted=1）的文件。
     */
    static class FilePermanentDeleteHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            try (BufferedReader br = new BufferedReader(new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                JsonObject req = gson.fromJson(br, JsonObject.class);
                if (req == null || !req.has("fileId")) {
                    sendErrorResponse(exchange, 400, "缺少参数：fileId");
                    return;
                }

                int fileId = req.get("fileId").getAsInt();

                dbLock.lock();
                try {
                    // 查询文件路径与状态
                    try (PreparedStatement pstmt = db.prepareStatement(
                            "SELECT filepath, is_deleted FROM files WHERE id = ? AND uploader_id = ?")) {
                        pstmt.setInt(1, fileId);
                        pstmt.setInt(2, userInfo.userId);
                        try (ResultSet rs = pstmt.executeQuery()) {
                            if (!rs.next()) {
                                sendErrorResponse(exchange, 404, "文件不存在或无权限");
                                return;
                            }
                            String filepath = rs.getString("filepath");
                            int isDeleted = rs.getInt("is_deleted");

                            if (isDeleted != 1) {
                                sendErrorResponse(exchange, 400, "文件未在回收站中，不能永久删除");
                                return;
                            }

                            // 删除物理文件
                            Path path = Paths.get(filepath);
                            try {
                                if (Files.exists(path)) {
                                    Files.delete(path);
                                    logger.info("已删除物理文件：" + filepath);
                                } else {
                                    logger.info("物理文件不存在，跳过删除：" + filepath);
                                }
                            } catch (IOException ex) {
                                logger.warning("删除物理文件失败：" + ex.getMessage());
                                // 继续尝试删除数据库记录
                            }

                            // 删除数据库记录
                            try (PreparedStatement delStmt = db.prepareStatement(
                                    "DELETE FROM files WHERE id = ?")) {
                                delStmt.setInt(1, fileId);
                                int affected = delStmt.executeUpdate();
                                Map<String, Object> resp = new HashMap<>();
                                resp.put("deleted", affected);
                                sendSuccessResponse(exchange, resp);
                                logger.info("永久删除文件记录，fileId=" + fileId + ", 用户=" + userInfo.username);
                                return;
                            }
                        }
                    }
                } catch (SQLException e) {
                    logger.severe("永久删除文件异常：" + e.getMessage());
                    sendErrorResponse(exchange, 500, "永久删除失败：" + e.getMessage());
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                logger.severe("永久删除接口异常：" + e.getMessage());
                sendErrorResponse(exchange, 500, "服务器内部错误");
            }
        }
    }

    /**
     * 文件下载接口（GET）
     */
    static class FileDownloadHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            // 解析fileId参数
            String query = exchange.getRequestURI().getQuery();
            if (query == null || !query.contains("fileId=")) {
                sendErrorResponse(exchange, 400, "无效参数，格式：?fileId=xxx");
                return;
            }

            String fileIdStr = query.split("fileId=")[1].trim();
            int fileId;
            try {
                fileId = Integer.parseInt(fileIdStr);
            } catch (NumberFormatException e) {
                sendErrorResponse(exchange, 400, "fileId必须是数字");
                return;
            }

            try {
                dbLock.lock();
                PreparedStatement pstmt = db.prepareStatement(
                        "SELECT filename, filepath, filesize, md5 FROM files " +
                        "WHERE id = ? AND uploader_id = ? AND is_deleted = 0");
                pstmt.setInt(1, fileId);
                pstmt.setInt(2, userInfo.userId);
                ResultSet rs = pstmt.executeQuery();

                if (!rs.next()) {
                    sendErrorResponse(exchange, 404, "文件不存在或无权限");
                    return;
                }

                String filename = rs.getString("filename");
                String filepath = rs.getString("filepath");
                long fileSize = rs.getLong("filesize");
                String storedMd5 = rs.getString("md5");
                Path filePath = Paths.get(filepath);

                // 校验文件完整性
                if (!Files.exists(filePath)) {
                    sendErrorResponse(exchange, 404, "文件已被删除或移动");
                    return;
                }
                if (Files.size(filePath) != fileSize) {
                    sendErrorResponse(exchange, 500, "文件大小不匹配，可能已被篡改");
                    return;
                }
                String actualMd5 = calculateFileMd5(filepath);
                if (!actualMd5.equals(storedMd5)) {
                    sendErrorResponse(exchange, 500, "文件内容已篡改，MD5校验失败");
                    return;
                }

                // 设置下载响应头
                exchange.getResponseHeaders().set("Content-Type", "application/octet-stream");
                exchange.getResponseHeaders().set("Content-Length", String.valueOf(fileSize));
                // 处理中文文件名编码
                String encodedFilename = URLEncoder.encode(filename, StandardCharsets.UTF_8.name())
                        .replace("+", "%20"); // 替换空格编码
                exchange.getResponseHeaders().set("Content-Disposition", 
                        "attachment; filename=\"" + encodedFilename + "\"");
                exchange.getResponseHeaders().set("Content-Transfer-Encoding", "binary");

                // 发送响应
                exchange.sendResponseHeaders(200, fileSize);

                // 流式传输文件
                try (BufferedInputStream in = new BufferedInputStream(Files.newInputStream(filePath));
                     BufferedOutputStream out = new BufferedOutputStream(exchange.getResponseBody())) {
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        out.write(buffer, 0, bytesRead);
                    }
                    out.flush();
                }

                logger.info("用户下载文件成功：" + userInfo.username + "（文件：" + filename + "）");
            } catch (Exception e) {
                logger.severe("文件下载异常：" + e.getMessage());
                try {
                    sendErrorResponse(exchange, 500, "文件下载失败：" + e.getMessage());
                } catch (IllegalStateException ex) {
                    // 忽略响应已发送的异常
                    logger.warning("下载响应已发送，无法返回错误信息：" + ex.getMessage());
                }
            } finally {
                dbLock.unlock();
            }
        }
    }

    /**
     * 文件预览接口（GET，仅支持文本文件）
     */
    static class FilePreviewHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            // 解析fileId参数
            String query = exchange.getRequestURI().getQuery();
            if (query == null || !query.contains("fileId=")) {
                sendErrorResponse(exchange, 400, "无效参数，格式：?fileId=xxx");
                return;
            }

            String fileIdStr = query.split("fileId=")[1].trim();
            int fileId;
            try {
                fileId = Integer.parseInt(fileIdStr);
            } catch (NumberFormatException e) {
                sendErrorResponse(exchange, 400, "fileId必须是数字");
                return;
            }

            try {
                dbLock.lock();
                PreparedStatement pstmt = db.prepareStatement(
                        "SELECT filename, filepath, filesize, file_type FROM files " +
                        "WHERE id = ? AND uploader_id = ? AND is_deleted = 0");
                pstmt.setInt(1, fileId);
                pstmt.setInt(2, userInfo.userId);
                ResultSet rs = pstmt.executeQuery();

                if (!rs.next()) {
                    sendErrorResponse(exchange, 404, "文件不存在或无权限");
                    return;
                }

                String filename = rs.getString("filename");
                String filepath = rs.getString("filepath");
                long fileSize = rs.getLong("filesize");
                String fileType = rs.getString("file_type");
                Path filePath = Paths.get(filepath);

                // 校验文件是否为文本类型
                if (!isTextFile(fileType, filePath)) {
                    sendErrorResponse(exchange, 403, "仅支持文本文件预览（.txt/.java/.json/.html等）");
                    return;
                }

                // 读取文件内容（限制前2KB预览，避免大文件占用资源）
                String content = Files.readString(filePath, StandardCharsets.UTF_8);
                String previewContent = content.substring(0, Math.min(2048, content.length()));
                boolean isTruncated = content.length() > 2048;

                // 响应结果
                Map<String, Object> previewData = new HashMap<>();
                previewData.put("filename", filename);
                previewData.put("fileSize", fileSize);
                previewData.put("content", previewContent);
                previewData.put("isTruncated", isTruncated);
                previewData.put("tip", isTruncated ? "仅显示前2KB内容，完整内容请下载" : "完整内容预览");

                sendSuccessResponse(exchange, previewData);
                logger.info("用户预览文件：" + userInfo.username + "（文件：" + filename + "）");
            } catch (Exception e) {
                logger.severe("文件预览异常：" + e.getMessage());
                sendErrorResponse(exchange, 500, "文件预览失败：" + e.getMessage());
            } finally {
                dbLock.unlock();
            }
        }

        /**
         * 判断是否为文本文件
         */
        private boolean isTextFile(String fileType, Path filePath) throws IOException {
            // 1. 通过MIME类型判断
            if (fileType != null && fileType.startsWith("text/")) {
                return true;
            }

            // 2. 通过文件后缀判断
            String filename = filePath.getFileName().toString().toLowerCase();
            String[] textExtensions = {".txt", ".java", ".html", ".htm", ".css", ".js", ".json", ".xml", ".md", ".csv", ".log"};
            for (String ext : textExtensions) {
                if (filename.endsWith(ext)) {
                    return true;
                }
            }

            // 3. 通过文件内容判断（前1KB非文本字符占比<10%）
            try (InputStream in = Files.newInputStream(filePath)) {
                byte[] buffer = new byte[1024];
                int bytesRead = in.read(buffer);
                if (bytesRead <= 0) {
                    return true; // 空文件视为文本
                }

                int nonTextCount = 0;
                for (int i = 0; i < bytesRead; i++) {
                    byte b = buffer[i];
                    // 允许：可打印字符（32-126）、换行（10）、回车（13）、制表符（9）
                    if (b < 9 || (b > 13 && b < 32) || b > 126) {
                        nonTextCount++;
                    }
                }

                return (nonTextCount * 100.0 / bytesRead) < 10;
            }
        }
    }

    // -------------------------- 回收站接口（需Token） --------------------------
    /**
     * 回收站文件列表（GET）
     */
    static class RecycleBinHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持GET方法");
                return;
            }

            try {
                dbLock.lock();
                PreparedStatement pstmt = db.prepareStatement(
                        "SELECT id, filename, filesize, delete_time FROM files " +
                        "WHERE uploader_id = ? AND is_deleted = 1 ORDER BY delete_time DESC");
                pstmt.setInt(1, userInfo.userId);
                ResultSet rs = pstmt.executeQuery();

                List<Map<String, Object>> recycleList = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> file = new HashMap<>();
                    file.put("id", rs.getInt("id"));
                    file.put("filename", rs.getString("filename"));
                    file.put("fileSize", rs.getLong("filesize"));
                    file.put("deleteTime", rs.getString("delete_time"));
                    recycleList.add(file);
                }

                sendSuccessResponse(exchange, recycleList);
                logger.info("用户查询回收站：" + userInfo.username + "（文件数：" + recycleList.size() + "）");
            } catch (SQLException e) {
                logger.severe("查询回收站异常：" + e.getMessage());
                sendErrorResponse(exchange, 500, "服务器内部错误");
            } finally {
                dbLock.unlock();
            }
        }
    }

    /**
     * 还原回收站文件（POST）
     */
    static class RestoreHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                JsonObject req = gson.fromJson(br, JsonObject.class);
                
                if (!req.has("fileId")) {
                    sendErrorResponse(exchange, 400, "缺少参数：fileId");
                    return;
                }
                
                int fileId = req.get("fileId").getAsInt();

                dbLock.lock();
                try {
                    // 查询文件信息
                    PreparedStatement pstmt = db.prepareStatement(
                            "SELECT filename FROM files WHERE id = ? AND uploader_id = ? AND is_deleted = 1");
                    pstmt.setInt(1, fileId);
                    pstmt.setInt(2, userInfo.userId);
                    ResultSet rs = pstmt.executeQuery();

                    if (!rs.next()) {
                        sendErrorResponse(exchange, 404, "文件不存在或无权限");
                        return;
                    }
                    String filename = rs.getString("filename");

                    // 从回收站移回上传目录
                    Path sourcePath = Paths.get(RECYCLE_DIR + File.separator + filename);
                    Path targetPath = Paths.get(UPLOAD_DIR + File.separator + filename);

                    // 若上传目录已有同名文件，添加时间戳后缀
                    if (Files.exists(targetPath)) {
                        String timestamp = String.valueOf(System.currentTimeMillis());
                        String newFilename = timestamp + "_" + filename;
                        targetPath = Paths.get(UPLOAD_DIR + File.separator + newFilename);
                        // 更新数据库文件名
                        pstmt = db.prepareStatement("UPDATE files SET filename = ? WHERE id = ?");
                        pstmt.setString(1, newFilename);
                        pstmt.setInt(2, fileId);
                        pstmt.executeUpdate();
                    }

                    Files.move(sourcePath, targetPath, StandardCopyOption.REPLACE_EXISTING);

                    // 更新数据库状态
                    pstmt = db.prepareStatement(
                            "UPDATE files SET is_deleted = 0, delete_time = NULL, filepath = ? WHERE id = ?");
                    pstmt.setString(1, targetPath.toString());
                    pstmt.setInt(2, fileId);
                    pstmt.executeUpdate();

                    sendSuccessResponse(exchange, null);
                    logger.info("用户还原文件：" + userInfo.username + "（文件：" + filename + "）");
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                logger.severe("还原文件异常：" + e.getMessage());
                sendErrorResponse(exchange, 500, "文件还原失败：" + e.getMessage());
            }
        }
    }

    /**
     * 清空回收站（POST）
     */
    static class EmptyRecycleHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            try {
                dbLock.lock();
                // 查询回收站文件
                PreparedStatement pstmt = db.prepareStatement(
                        "SELECT filename FROM files WHERE uploader_id = ? AND is_deleted = 1");
                pstmt.setInt(1, userInfo.userId);
                ResultSet rs = pstmt.executeQuery();

                // 删除物理文件
                int deleteCount = 0;
                while (rs.next()) {
                    String filename = rs.getString("filename");
                    Path filePath = Paths.get(RECYCLE_DIR + File.separator + filename);
                    if (Files.exists(filePath)) {
                        Files.delete(filePath);
                        deleteCount++;
                    }
                }

                // 删除数据库记录
                pstmt = db.prepareStatement(
                        "DELETE FROM files WHERE uploader_id = ? AND is_deleted = 1");
                pstmt.setInt(1, userInfo.userId);
                pstmt.executeUpdate();

                sendSuccessResponse(exchange, Map.of("deletedCount", deleteCount));
                logger.info("用户清空回收站：" + userInfo.username + "（删除文件数：" + deleteCount + "）");
            } catch (Exception e) {
                logger.severe("清空回收站异常：" + e.getMessage());
                sendErrorResponse(exchange, 500, "清空回收站失败：" + e.getMessage());
            } finally {
                dbLock.unlock();
            }
        }
    }

    // -------------------------- 资源释放与关闭钩子 --------------------------
    /**
     * JVM关闭钩子：释放数据库连接等资源
     */
    static {
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
}