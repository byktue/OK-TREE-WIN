import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantLock;
import com.google.gson.*;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.nio.charset.StandardCharsets;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import java.security.Key;

import java.util.Date;

public class HttpFileServer {
    private static final int PORT = 3000;
    private static final String STORAGE_DIR = "server_storage";
    private static final String RECYCLE_DIR = "recycle_bin";
    private static final String UPLOAD_DIR = STORAGE_DIR + File.separator + "uploads";

    // JWT配置（生产环境建议用32位以上随机密钥，存储在配置文件）
    private static final String JWT_SECRET = "x8V2#zQ9!pL7@wK3$rT5*yB1&mN4%vF6^gH8(jU0)tR2";
    private static final long JWT_EXPIRE = 8 * 60 * 60 * 1000; // 8小时过期（更安全）
    private static final Key JWT_KEY = Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));

    // 数据库连接和锁
    private static Connection db;
    private static final ReentrantLock dbLock = new ReentrantLock();
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public static void main(String[] args) throws IOException, SQLException {
        // 初始化目录
        Files.createDirectories(Paths.get(STORAGE_DIR));
        Files.createDirectories(Paths.get(UPLOAD_DIR));
        Files.createDirectories(Paths.get(RECYCLE_DIR));

        // 初始化数据库
        initDatabase();

        // 启动HTTP服务器
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        
        // 无需认证的接口（登录、注册）
        server.createContext("/api/auth/login", new LoggingHandler(new LoginHandler()));
        server.createContext("/api/register", new LoggingHandler(new RegisterHandler()));
        
        // 需要Token认证的接口（继承AbstractTokenHandler）
        server.createContext("/api/user/profile", new LoggingHandler(new UserProfileHandler()));
        server.createContext("/api/user/change-password", new LoggingHandler(new ChangePasswordHandler()));
        server.createContext("/api/files", new LoggingHandler(new FileListHandler()));
        server.createContext("/api/files/upload", new LoggingHandler(new FileUploadHandler()));
        server.createContext("/api/files/delete", new LoggingHandler(new FileDeleteHandler()));
        server.createContext("/api/files/download", new LoggingHandler(new FileDownloadHandler()));
        server.createContext("/api/files/preview", new LoggingHandler(new FilePreviewHandler()));
        server.createContext("/api/recycle-bin", new LoggingHandler(new RecycleBinHandler()));
        server.createContext("/api/recycle-bin/restore", new LoggingHandler(new RestoreHandler()));
        server.createContext("/api/recycle-bin/empty", new LoggingHandler(new EmptyRecycleHandler()));
        server.createContext("/api/admin/delete-user", new LoggingHandler(new AdminDeleteUserHandler()));

        server.setExecutor(Executors.newFixedThreadPool(10));
        server.start();
        System.out.println("HTTP文件服务器已启动，监听端口 " + PORT);
    }

    // -------------------------- JWT工具方法 --------------------------
    /**
     * 生成JWT Token
     */
    private static String generateToken(int userId, String username, boolean isAdmin, boolean isMember) {
        return Jwts.builder()
                .setSubject(String.valueOf(userId)) // 用户ID作为Subject
                .claim("username", username)       // 自定义声明：用户名
                .claim("isAdmin", isAdmin)         // 自定义声明：是否管理员
                .claim("isMember", isMember)       // 自定义声明：是否会员
                .setExpiration(new Date(System.currentTimeMillis() + JWT_EXPIRE)) // 过期时间
                .signWith(JWT_KEY, SignatureAlgorithm.HS256) // 签名算法
                .compact();
    }

    /**
     * 解析JWT Token，返回用户信息（null表示Token无效）
     */
    private static UserTokenInfo parseToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(JWT_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // 提取Token中的用户信息
            return new UserTokenInfo(
                    Integer.parseInt(claims.getSubject()),
                    claims.get("username", String.class),
                    claims.get("isAdmin", Boolean.class),
                    claims.get("isMember", Boolean.class)
            );
        } catch (JwtException | IllegalArgumentException e) {
            return null; // Token过期、无效或签名错误
        }
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

    // -------------------------- 抽象Token验证Handler --------------------------
    /**
     * 所有需要Token认证的接口都继承此类，统一处理Token验证和CORS
     */
    static abstract class AbstractTokenHandler implements HttpHandler {
        protected UserTokenInfo userInfo; // 验证通过后的用户信息

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // 处理CORS预检请求（关键修改：所有需认证接口都加CORS）
            handleCorsPreflight(exchange);
            if ("OPTIONS".equals(exchange.getRequestMethod())) {
                return;
            }

            // 1. 从请求头获取Token（格式：Authorization: Bearer <token>）
            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                sendErrorResponse(exchange, 401, "未提供有效Token（格式：Bearer <token>）");
                return;
            }

            // 2. 提取Token（去除"Bearer "前缀）
            String token = authHeader.substring(7).trim();
            userInfo = parseToken(token);

            // 3. 验证Token有效性
            if (userInfo == null) {
                sendErrorResponse(exchange, 401, "Token无效或已过期");
                return;
            }

            // 4. 验证通过，调用子类业务逻辑
            handleWithAuth(exchange);
        }

        /**
         * 子类实现具体业务逻辑（已通过Token验证）
         */
        protected abstract void handleWithAuth(HttpExchange exchange) throws IOException;

        /**
         * 通用错误响应
         */
        protected void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
            sendResponse(exchange, statusCode, Map.of("success", false, "message", message));
        }
    }

    // -------------------------- 基础工具方法 --------------------------
    private static void initDatabase() throws SQLException {
        db = DriverManager.getConnection("jdbc:sqlite:file_server.db");
        
        try (Statement stmt = db.createStatement()) {
            // 用户表
            stmt.execute("CREATE TABLE IF NOT EXISTS users (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "username TEXT UNIQUE NOT NULL, " +
                    "password TEXT NOT NULL, " +
                    "nickname TEXT, " +
                    "email TEXT, " +
                    "is_admin INTEGER DEFAULT 0, " +
                    "is_member INTEGER DEFAULT 0, " +
                    "created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
            
            // 文件表
            stmt.execute("CREATE TABLE IF NOT EXISTS files (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "filename TEXT NOT NULL, " +
                    "filepath TEXT UNIQUE NOT NULL, " +
                    "filesize INTEGER NOT NULL, " +
                    "md5 TEXT NOT NULL, " +
                    "uploader_id INTEGER NOT NULL, " +
                    "upload_time DATETIME DEFAULT CURRENT_TIMESTAMP, " +
                    "is_deleted INTEGER DEFAULT 0, " +
                    "delete_time DATETIME, " +
                    "FOREIGN KEY(uploader_id) REFERENCES users(id))");
            
            // 初始化管理员账户（admin/admin123，与前端测试账号对齐）
            ResultSet rs = stmt.executeQuery("SELECT id FROM users WHERE username = 'admin'");
            if (!rs.next()) {
                stmt.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', 'admin123', 1)");
                System.out.println("默认管理员账户已创建：admin/admin123");
            }
            // 初始化测试账户（test/test123）
            rs = stmt.executeQuery("SELECT id FROM users WHERE username = 'test'");
            if (!rs.next()) {
                stmt.execute("INSERT INTO users (username, password) VALUES ('test', 'test123')");
                System.out.println("测试账户已创建：test/test123");
            }
        }
    }

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

    // CORS 预检请求处理方法（全局统一配置，支持所有必要方法）
    private static void handleCorsPreflight(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
        exchange.getResponseHeaders().set("Access-Control-Max-Age", "86400");

        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            // 显式设置空响应体，避免Content-Length误判
            exchange.sendResponseHeaders(204, 0);
            exchange.getResponseBody().close(); // 立即关闭响应体，确保无内容
        }
    }

    // 统一响应方法（补充完整CORS头，确保前端能解析）
    private static void sendResponse(HttpExchange exchange, int statusCode, Object response) throws IOException {
        String json = gson.toJson(response);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        // 完整CORS响应头（与预检请求保持一致，避免跨域错误）
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Authorization, Content-Type");
        exchange.sendResponseHeaders(statusCode, json.getBytes(StandardCharsets.UTF_8).length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(json.getBytes(StandardCharsets.UTF_8));
        }
    }

    
    // -------------------------- 日志包装Handler --------------------------
    static class LoggingHandler implements HttpHandler {
        private final HttpHandler delegate;

        LoggingHandler(HttpHandler delegate) {
            this.delegate = delegate;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // 打印请求日志（便于调试）
            System.out.printf("[%s] %s %s%n", 
                    new Date(), 
                    exchange.getRequestMethod(), 
                    exchange.getRequestURI());
            delegate.handle(exchange);
        }
    }

    // -------------------------- 认证相关接口 --------------------------
    // 登录接口（核心优化：响应格式与前端完全对齐，错误明确返回success:false）
    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // 处理CORS预检请求
            handleCorsPreflight(exchange);
            if ("OPTIONS".equals(exchange.getRequestMethod())) {
                return;
            }

            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, Map.of("success", false, "message", "只支持POST方法"));
                return;
            }

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                JsonObject req = gson.fromJson(br, JsonObject.class);
                
                // 校验请求参数（避免空指针）
                if (!req.has("username") || !req.has("password")) {
                    sendResponse(exchange, 400, Map.of("success", false, "message", "缺少用户名或密码参数"));
                    return;
                }
                
                String username = req.get("username").getAsString().trim();
                String password = req.get("password").getAsString().trim();

                dbLock.lock();
                try (PreparedStatement pstmt = db.prepareStatement(
                        "SELECT id, is_admin, is_member FROM users WHERE username = ? AND password = ?")) {
                    pstmt.setString(1, username);
                    pstmt.setString(2, password);
                    ResultSet rs = pstmt.executeQuery();

                    if (rs.next()) {
                        // 生成JWT Token
                        String token = generateToken(
                                rs.getInt("id"),
                                username,
                                rs.getInt("is_admin") == 1,
                                rs.getInt("is_member") == 1
                        );

                        // 成功响应：与前端约定的格式（success:true + token + user）
                        sendResponse(exchange, 200, Map.of(
                                "success", true,
                                "message", "登录成功",
                                "token", token, // 前端需保存此Token用于后续接口
                                "user", Map.of(
                                        "id", rs.getInt("id"),
                                        "username", username,
                                        "isAdmin", rs.getInt("is_admin") == 1,
                                        "isMember", rs.getInt("is_member") == 1
                                )
                        ));
                    } else {
                        // 失败响应：明确返回success:false，前端不跳转
                        sendResponse(exchange, 401, Map.of("success", false, "message", "用户名或密码错误"));
                    }
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                // 服务器错误：统一返回success:false
                sendResponse(exchange, 500, Map.of("success", false, "message", "服务器错误: " + e.getMessage()));
            }
        }
    }

    // 注册接口（优化：错误响应格式统一）
    static class RegisterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // 处理CORS预检请求
            handleCorsPreflight(exchange);
            if ("OPTIONS".equals(exchange.getRequestMethod())) {
                return;
            }

            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, Map.of("success", false, "message", "只支持POST方法"));
                return;
            }

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                JsonObject req = gson.fromJson(br, JsonObject.class);
                
                // 校验参数
                if (!req.has("username") || !req.has("password")) {
                    sendResponse(exchange, 400, Map.of("success", false, "message", "缺少用户名或密码参数"));
                    return;
                }
                
                String username = req.get("username").getAsString().trim();
                String password = req.get("password").getAsString().trim();

                // 简单参数校验
                if (username.length() < 3 || password.length() < 6) {
                    sendResponse(exchange, 400, Map.of("success", false, "message", "用户名至少3位，密码至少6位"));
                    return;
                }

                dbLock.lock();
                try (PreparedStatement pstmt = db.prepareStatement(
                        "INSERT INTO users (username, password) VALUES (?, ?)")) {
                    pstmt.setString(1, username);
                    pstmt.setString(2, password);
                    pstmt.executeUpdate();
                    sendResponse(exchange, 200, Map.of("success", true, "message", "注册成功，请登录"));
                } catch (SQLException e) {
                    sendResponse(exchange, 400, Map.of("success", false, "message", "用户名已存在"));
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                sendResponse(exchange, 500, Map.of("success", false, "message", "服务器错误: " + e.getMessage()));
            }
        }
    }


    // -------------------------- 用户相关接口（需Token） --------------------------
    // 用户信息接口（GET获取/POST修改）
    static class UserProfileHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    // 获取用户信息
                    dbLock.lock();
                    try (PreparedStatement pstmt = db.prepareStatement(
                            "SELECT username, nickname, email, is_admin, is_member FROM users WHERE id = ?")) {
                        pstmt.setInt(1, userInfo.userId); // 使用Token解析的用户ID
                        ResultSet rs = pstmt.executeQuery();
                        
                        if (rs.next()) {
                            Map<String, Object> user = new HashMap<>();
                            user.put("username", rs.getString("username"));
                            user.put("nickname", rs.getString("nickname") != null ? rs.getString("nickname") : "");
                            user.put("email", rs.getString("email") != null ? rs.getString("email") : "");
                            user.put("isAdmin", rs.getInt("is_admin") == 1);
                            user.put("isMember", rs.getInt("is_member") == 1);
                            
                            sendResponse(exchange, 200, Map.of("success", true, "data", user));
                        } else {
                            sendErrorResponse(exchange, 404, "用户不存在");
                        }
                    } finally {
                        dbLock.unlock();
                    }
                } else if ("PUT".equals(exchange.getRequestMethod())) {
                    // 修改用户信息
                    JsonObject req = gson.fromJson(
                            new InputStreamReader(exchange.getRequestBody()), JsonObject.class);
                    
                    // 校验参数
                    if (!req.has("nickname") || !req.has("email")) {
                        sendErrorResponse(exchange, 400, "缺少昵称或邮箱参数");
                        return;
                    }
                    
                    dbLock.lock();
                    try (PreparedStatement pstmt = db.prepareStatement(
                            "UPDATE users SET nickname = ?, email = ? WHERE id = ?")) {
                        pstmt.setString(1, req.get("nickname").getAsString().trim());
                        pstmt.setString(2, req.get("email").getAsString().trim());
                        pstmt.setInt(3, userInfo.userId);
                        pstmt.executeUpdate();
                        sendResponse(exchange, 200, Map.of("success", true, "message", "信息更新成功"));
                    } finally {
                        dbLock.unlock();
                    }
                } else {
                    sendErrorResponse(exchange, 405, "不支持的方法");
                }
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "服务器错误: " + e.getMessage());
            }
        }
    }

    // 密码修改接口
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
                    sendErrorResponse(exchange, 400, "缺少旧密码或新密码参数");
                    return;
                }
                
                String oldPwd = req.get("oldPassword").getAsString().trim();
                String newPwd = req.get("newPassword").getAsString().trim();

                // 新密码强度校验
                if (newPwd.length() < 6) {
                    sendErrorResponse(exchange, 400, "新密码至少6位");
                    return;
                }

                dbLock.lock();
                try {
                    // 验证旧密码
                    PreparedStatement pstmt = db.prepareStatement(
                            "SELECT id FROM users WHERE id = ? AND password = ?");
                    pstmt.setInt(1, userInfo.userId);
                    pstmt.setString(2, oldPwd);
                    ResultSet rs = pstmt.executeQuery();
                    
                    if (!rs.next()) {
                        sendErrorResponse(exchange, 400, "旧密码错误");
                        return;
                    }

                    // 更新新密码
                    pstmt = db.prepareStatement("UPDATE users SET password = ? WHERE id = ?");
                    pstmt.setString(1, newPwd);
                    pstmt.setInt(2, userInfo.userId);
                    pstmt.executeUpdate();
                    
                    sendResponse(exchange, 200, Map.of("success", true, "message", "密码修改成功，请重新登录"));
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "服务器错误: " + e.getMessage());
            }
        }
    }

    // -------------------------- 管理员接口（需Token+管理员权限） --------------------------
    static class AdminDeleteUserHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            // 额外验证管理员权限
            if (!userInfo.isAdmin) {
                sendErrorResponse(exchange, 403, "无管理员权限，无法删除用户");
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

                // 禁止删除自己
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
                    deleteUserFiles(targetUserId, UPLOAD_DIR);
                    deleteUserFiles(targetUserId, RECYCLE_DIR);

                    // 删除用户记录
                    pstmt = db.prepareStatement("DELETE FROM users WHERE id = ?");
                    pstmt.setInt(1, targetUserId);
                    int affectedRows = pstmt.executeUpdate();

                    if (affectedRows > 0) {
                        sendResponse(exchange, 200, Map.of("success", true, "message", "用户删除成功（含关联文件）"));
                    } else {
                        sendErrorResponse(exchange, 500, "用户删除失败");
                    }
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "服务器错误: " + e.getMessage());
            }
        }

        // 辅助方法：删除用户关联文件
        private void deleteUserFiles(int userId, String targetDir) throws SQLException, IOException {
            // 删除物理文件
            try (PreparedStatement pstmt = db.prepareStatement(
                    "SELECT filepath FROM files WHERE uploader_id = ?")) {
                pstmt.setInt(1, userId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        Path fileToDelete = Paths.get(rs.getString("filepath"));
                        if (Files.exists(fileToDelete)) {
                            Files.delete(fileToDelete);
                            System.out.println("已删除用户文件: " + fileToDelete);
                        }
                    }
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
    // 文件列表接口
    static class FileListHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            try {
                dbLock.lock();
                // 打印查询条件，方便调试
                System.out.println("查询文件列表 - 用户ID: " + userInfo.userId);
                
                PreparedStatement pstmt = db.prepareStatement(
                        "SELECT id, filename, filesize, upload_time FROM files " +
                        "WHERE uploader_id = ? AND is_deleted = 0");
                pstmt.setInt(1, userInfo.userId);
                ResultSet rs = pstmt.executeQuery();

                List<Map<String, Object>> files = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> file = new HashMap<>();
                    file.put("id", rs.getInt("id"));
                    file.put("filename", rs.getString("filename"));
                    file.put("filesize", rs.getLong("filesize"));
                    file.put("uploadTime", rs.getString("upload_time"));
                    files.add(file);
                }
                
                // 打印查询结果数量
                System.out.println("文件列表查询结果 - 数量: " + files.size());
                sendResponse(exchange, 200, Map.of("success", true, "data", files));
            } catch (SQLException e) {
                System.err.println("文件列表查询失败（数据库错误）: " + e.getMessage());
                sendErrorResponse(exchange, 500, "服务器错误: 数据库查询失败");
            } catch (Exception e) {
                System.err.println("文件列表查询失败: " + e.getMessage());
                sendErrorResponse(exchange, 500, "服务器错误: " + e.getMessage());
            } finally {
                dbLock.unlock();
            }
        }
    }
    
    // 文件上传接口
    static class FileUploadHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            // 1. 解析Content-Type和boundary
            String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            if (contentType == null || !contentType.startsWith("multipart/form-data")) {
                sendErrorResponse(exchange, 400, "无效的请求格式（需为multipart/form-data）");
                return;
            }
            String boundary = extractBoundary(contentType);
            if (boundary == null) {
                sendErrorResponse(exchange, 400, "无法解析multipart边界");
                return;
            }
            String boundaryDelimiter = "--" + boundary;
            byte[] boundaryBytes = boundaryDelimiter.getBytes(StandardCharsets.UTF_8);
            byte[] endBoundaryBytes = (boundaryDelimiter + "--").getBytes(StandardCharsets.UTF_8);
            System.out.println("解析到boundary: " + boundary);

            // 2. 读取完整请求体（字节流，避免编码转换）
            byte[] fullBody;
            try (InputStream requestIn = exchange.getRequestBody();
                ByteArrayOutputStream byteOut = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = requestIn.read(buffer)) != -1) {
                    byteOut.write(buffer, 0, bytesRead);
                }
                fullBody = byteOut.toByteArray();
            }

            // 3. 提取文件名（通过字符串解析，但不影响文件内容）
            String fullBodyStr = new String(fullBody, StandardCharsets.UTF_8);
            String originalFilename = extractFilename(fullBodyStr);
            if (originalFilename == null || originalFilename.isEmpty()) {
                sendErrorResponse(exchange, 400, "未获取到文件名");
                return;
            }
            System.out.println("提取到原始文件名: " + originalFilename);

            // 4. 提取文件内容（纯字节流操作，避免编码转换）
            byte[] fileContent = null;
            int startIndex = -1;
            int endIndex = -1;

            // 查找文件内容起始位置（\r\n\r\n之后）
            byte[] contentStartMarker = "\r\n\r\n".getBytes(StandardCharsets.UTF_8);
            startIndex = indexOf(fullBody, contentStartMarker);
            if (startIndex == -1) {
                sendErrorResponse(exchange, 400, "无法找到文件内容起始位置");
                return;
            }
            startIndex += contentStartMarker.length; // 跳过\r\n\r\n

            // 查找文件内容结束位置（结束边界之前）
            endIndex = indexOf(fullBody, endBoundaryBytes, startIndex);
            if (endIndex == -1) {
                // 兼容不含--的边界（单文件场景）
                endIndex = indexOf(fullBody, boundaryBytes, startIndex);
            }
            if (endIndex == -1) {
                // 兜底：取到请求体末尾（可能包含无关内容，但优先保证文件完整）
                endIndex = fullBody.length;
            } else {
                // 去除结束边界前的换行符
                if (endIndex >= 2 && fullBody[endIndex - 2] == '\r' && fullBody[endIndex - 1] == '\n') {
                    endIndex -= 2;
                }
            }

            // 提取文件内容字节数组
            if (startIndex < endIndex) {
                fileContent = Arrays.copyOfRange(fullBody, startIndex, endIndex);
            } else {
                sendErrorResponse(exchange, 400, "文件内容为空或无效");
                return;
            }

            // 5. 写入文件（直接用字节数组，确保二进制完整）
            String ext = originalFilename.contains(".") ? 
                originalFilename.substring(originalFilename.lastIndexOf(".")) : ".txt";
            String savedFilename = "upload_" + System.currentTimeMillis() + ext;
            String savedFilepath = UPLOAD_DIR + File.separator + savedFilename;
            Path savedFilePath = Paths.get(savedFilepath);
            Files.write(savedFilePath, fileContent);
            System.out.println("文件写入成功: " + savedFilepath + " (" + fileContent.length + " bytes)");

            // 6. 保存到数据库（记录MD5用于校验）
            try {
                long fileSize = Files.size(savedFilePath);
                String md5 = calculateFileMd5(savedFilepath);

                dbLock.lock();
                try (PreparedStatement pstmt = db.prepareStatement(
                        "INSERT INTO files (filename, filepath, filesize, md5, uploader_id) VALUES (?, ?, ?, ?, ?)")) {
                    pstmt.setString(1, savedFilename);
                    pstmt.setString(2, savedFilepath);
                    pstmt.setLong(3, fileSize);
                    pstmt.setString(4, md5);
                    pstmt.setInt(5, userInfo.userId);
                    pstmt.executeUpdate();
                    System.out.println("数据库插入成功: " + savedFilename + " (MD5: " + md5 + ")");
                } finally {
                    dbLock.unlock();
                }

                // 7. 响应结果
                sendResponse(exchange, 200, Map.of(
                        "success", true, 
                        "message", "文件上传成功",
                        "data", Map.of(
                                "originalFilename", originalFilename,
                                "savedFilename", savedFilename,
                                "filesize", fileSize,
                                "md5", md5
                        )
                ));
            } catch (Exception e) {
                System.err.println("上传失败: " + e.getMessage());
                if (Files.exists(savedFilePath)) {
                    Files.delete(savedFilePath);
                }
                sendErrorResponse(exchange, 500, "服务器错误: " + e.getMessage());
            }
        }

        // 辅助方法：提取boundary
        private String extractBoundary(String contentType) {
            String[] parts = contentType.split(";");
            for (String part : parts) {
                part = part.trim();
                if (part.startsWith("boundary=")) {
                    String boundary = part.substring("boundary=".length()).trim();
                    if (boundary.startsWith("\"") && boundary.endsWith("\"")) {
                        boundary = boundary.substring(1, boundary.length() - 1);
                    }
                    return boundary.isEmpty() ? null : boundary;
                }
            }
            return null;
        }

        // 辅助方法：提取文件名
        private String extractFilename(String content) {
            String[] lines = content.split("\r\n");
            for (String line : lines) {
                if (line.contains("filename=")) {
                    String[] parts = line.split("filename=");
                    if (parts.length >= 2) {
                        String filename = parts[1].trim();
                        if (filename.startsWith("\"") && filename.endsWith("\"")) {
                            filename = filename.substring(1, filename.length() - 1);
                        }
                        return filename.isEmpty() ? null : filename;
                    }
                }
            }
            return null;
        }

        // 辅助方法：从指定位置开始查找字节数组
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

        // 辅助方法：查找字节数组（从起始位置）
        private int indexOf(byte[] source, byte[] target) {
            return indexOf(source, target, 0);
        }
    }
    
    // 文件删除接口（移至回收站）
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
                            "SELECT filepath FROM files WHERE id = ? AND uploader_id = ?");
                    pstmt.setInt(1, fileId);
                    pstmt.setInt(2, userInfo.userId);
                    ResultSet rs = pstmt.executeQuery();

                    if (!rs.next()) {
                        sendErrorResponse(exchange, 404, "文件不存在或无权限");
                        return;
                    }
                    String filepath = rs.getString("filepath");

                    // 移动文件到回收站
                    Path source = Paths.get(filepath);
                    Path target = Paths.get(RECYCLE_DIR + File.separator + source.getFileName().toString());
                    Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);

                    // 更新数据库状态
                    pstmt = db.prepareStatement(
                            "UPDATE files SET is_deleted = 1, delete_time = CURRENT_TIMESTAMP WHERE id = ?");
                    pstmt.setInt(1, fileId);
                    pstmt.executeUpdate();

                    sendResponse(exchange, 200, Map.of("success", true, "message", "文件已移至回收站"));
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "服务器错误: " + e.getMessage());
            }
        }
    }

    // 文件下载接口（强化CORS配置）
    static class FileDownloadHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            // 解析URL中的fileId参数
            String query = exchange.getRequestURI().getQuery();
            if (query == null || !query.contains("=")) {
                sendErrorResponse(exchange, 400, "无效的文件ID参数（格式：?fileId=1）");
                return;
            }
            String fileIdStr = query.split("=")[1];
            int fileId;
            try {
                fileId = Integer.parseInt(fileIdStr);
            } catch (NumberFormatException e) {
                sendErrorResponse(exchange, 400, "文件ID必须是数字");
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
                long filesize = rs.getLong("filesize");
                String storedMd5 = rs.getString("md5");
                Path filePath = Paths.get(filepath);

                // 校验文件有效性（确保上传后未被篡改）
                if (!Files.exists(filePath)) {
                    sendErrorResponse(exchange, 404, "文件已被删除或移动");
                    return;
                }
                long actualSize = Files.size(filePath);
                if (actualSize != filesize) {
                    sendErrorResponse(exchange, 500, 
                            String.format("文件大小不匹配（存储：%d，实际：%d）", filesize, actualSize));
                    return;
                }
                String actualMd5 = calculateFileMd5(filepath);
                if (!actualMd5.equals(storedMd5)) {
                    sendErrorResponse(exchange, 500, 
                            String.format("文件内容已篡改（存储MD5：%s，实际：%s）", storedMd5, actualMd5));
                    return;
                }

                // 强化CORS头，确保下载跨域无问题
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE");
                exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Authorization, Content-Type");
                
                // 发送文件流（纯字节传输，无编码转换）
                exchange.getResponseHeaders().set("Content-Type", "application/octet-stream");
                exchange.getResponseHeaders().set("Content-Disposition", 
                        "attachment; filename=\"" + URLEncoder.encode(filename, StandardCharsets.UTF_8.name()) + "\"");
                exchange.getResponseHeaders().set("Content-Length", String.valueOf(filesize));
                exchange.sendResponseHeaders(200, filesize);

                // 缓冲流传输（字节级完整复制）
                try (BufferedOutputStream os = new BufferedOutputStream(exchange.getResponseBody());
                    BufferedInputStream is = new BufferedInputStream(Files.newInputStream(filePath))) {
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = is.read(buffer)) != -1) {
                        os.write(buffer, 0, bytesRead); // 严格按读取的字节数写入
                    }
                    os.flush(); // 确保最后一批数据发送
                }
                System.out.println("文件下载成功: " + filename + "（大小：" + filesize + " bytes，MD5：" + storedMd5 + "）");

            } catch (Exception e) {
                try {
                    sendErrorResponse(exchange, 500, "服务器错误: " + e.getMessage());
                } catch (IllegalStateException ex) {
                    System.err.println("下载文件出错: " + e.getMessage());
                }
            } finally {
                dbLock.unlock();
            }
        }
    }
    
    // 文件预览接口（仅文本文件）
    static class FilePreviewHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            // 解析fileId参数
            String query = exchange.getRequestURI().getQuery();
            if (query == null || !query.contains("=")) {
                sendErrorResponse(exchange, 400, "无效的文件ID参数（格式：?fileId=1）");
                return;
            }
            String fileIdStr = query.split("=")[1];
            int fileId;
            try {
                fileId = Integer.parseInt(fileIdStr);
            } catch (NumberFormatException e) {
                sendErrorResponse(exchange, 400, "文件ID必须是数字");
                return;
            }

            try {
                dbLock.lock();
                PreparedStatement pstmt = db.prepareStatement(
                        "SELECT filename, filepath, filesize FROM files " +
                        "WHERE id = ? AND uploader_id = ? AND is_deleted = 0");
                pstmt.setInt(1, fileId);
                pstmt.setInt(2, userInfo.userId);
                ResultSet rs = pstmt.executeQuery();

                if (!rs.next()) {
                    sendErrorResponse(exchange, 404, "文件不存在或无权限");
                    return;
                }

                String filepath = rs.getString("filepath");
                String filename = rs.getString("filename");
                long filesize = rs.getLong("filesize");
                Path filePath = Paths.get(filepath);

                // 判断是否为文本文件（支持预览）
                if (!isTextFile(filename, filePath)) {
                    sendErrorResponse(exchange, 403, "仅支持文本文件预览（.txt/.java/.html/.json等）");
                    return;
                }

                // 读取文件内容（限制前1KB预览）
                String content = Files.readString(filePath, StandardCharsets.UTF_8);
                sendResponse(exchange, 200, Map.of(
                        "success", true,
                        "data", Map.of(
                                "filename", filename,
                                "content", content.substring(0, Math.min(1024, content.length())),
                                "totalSize", filesize,
                                "previewTip", "仅显示前1KB内容，完整内容请下载"
                        )
                ));
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "服务器错误: " + e.getMessage());
            } finally {
                dbLock.unlock();
            }
        }

        // 判断是否为文本文件（基于后缀和内容）
        private boolean isTextFile(String filename, Path filePath) throws IOException {
            // 1. 优先通过后缀判断
            String lowerFilename = filename.toLowerCase();
            String[] textExtensions = {".txt", ".java", ".html", ".json", ".xml", ".css", ".js", ".md", ".json", ".csv"};
            for (String ext : textExtensions) {
                if (lowerFilename.endsWith(ext)) {
                    return true;
                }
            }

            // 2. 后缀不匹配时，检测文件前1KB内容
            try (InputStream is = Files.newInputStream(filePath)) {
                byte[] buffer = new byte[1024];
                int bytesRead = is.read(buffer);
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

                // 非文本字符占比低于10%则视为文本
                return (nonTextCount * 100.0 / bytesRead) < 10;
            }
        }
    }

    // -------------------------- 回收站接口（需Token） --------------------------
    // 回收站文件列表
    static class RecycleBinHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            try {
                dbLock.lock();
                PreparedStatement pstmt = db.prepareStatement(
                        "SELECT id, filename, filesize, delete_time FROM files " +
                        "WHERE uploader_id = ? AND is_deleted = 1");
                pstmt.setInt(1, userInfo.userId);
                ResultSet rs = pstmt.executeQuery();

                List<Map<String, Object>> files = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> file = new HashMap<>();
                    file.put("id", rs.getInt("id"));
                    file.put("filename", rs.getString("filename"));
                    file.put("filesize", rs.getLong("filesize"));
                    file.put("deleteTime", rs.getString("delete_time"));
                    files.add(file);
                }

                sendResponse(exchange, 200, Map.of("success", true, "data", files));
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "服务器错误: " + e.getMessage());
            } finally {
                dbLock.unlock();
            }
        }
    }

    // 还原回收站文件
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
                    // 查询文件信息（验证归属）
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
                    Path source = Paths.get(RECYCLE_DIR + File.separator + filename);
                    Path target = Paths.get(UPLOAD_DIR + File.separator + filename);
                    Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);

                    // 更新数据库状态
                    pstmt = db.prepareStatement(
                            "UPDATE files SET is_deleted = 0, delete_time = NULL WHERE id = ?");
                    pstmt.setInt(1, fileId);
                    pstmt.executeUpdate();

                    sendResponse(exchange, 200, Map.of("success", true, "message", "文件已还原"));
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "服务器错误: " + e.getMessage());
            }
        }
    }

    // 清空回收站
    static class EmptyRecycleHandler extends AbstractTokenHandler {
        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            try {
                dbLock.lock();
                // 查询用户回收站文件
                PreparedStatement pstmt = db.prepareStatement(
                        "SELECT filename FROM files WHERE uploader_id = ? AND is_deleted = 1");
                pstmt.setInt(1, userInfo.userId);
                ResultSet rs = pstmt.executeQuery();

                // 收集文件名并删除物理文件
                List<String> filenames = new ArrayList<>();
                while (rs.next()) {
                    filenames.add(rs.getString("filename"));
                }
                for (String filename : filenames) {
                    Files.deleteIfExists(Paths.get(RECYCLE_DIR + File.separator + filename));
                }

                // 删除数据库记录
                pstmt = db.prepareStatement(
                        "DELETE FROM files WHERE uploader_id = ? AND is_deleted = 1");
                pstmt.setInt(1, userInfo.userId);
                pstmt.executeUpdate();

                sendResponse(exchange, 200, Map.of("success", true, "message", "回收站已清空"));
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "服务器错误: " + e.getMessage());
            } finally {
                dbLock.unlock();
            }
        }
    }
}