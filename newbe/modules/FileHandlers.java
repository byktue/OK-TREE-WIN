import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 文件上传/下载/列表等 Handler。
 */
public final class FileHandlers {
    private FileHandlers() {}

    public static class FileListHandler extends AbstractTokenHandler {
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持GET方法");
                return;
            }

            Map<String, String> queryParams = FileHelper.parseQueryParams(exchange.getRequestURI().getQuery());
            Integer folderId = null;
            if (queryParams.containsKey("folderId") && !queryParams.get("folderId").isBlank()) {
                try {
                    folderId = Integer.parseInt(queryParams.get("folderId"));
                } catch (NumberFormatException e) {
                    sendErrorResponse(exchange, 400, "folderId 必须是数字");
                    return;
                }
            }

            FolderService.FolderInfo currentFolder = null;
            if (folderId != null) {
                try {
                    currentFolder = FolderService.getFolderInfo(folderId, userInfo.userId);
                } catch (SQLException ex) {
                    if (ServerContext.getLogger() != null) {
                        ServerContext.getLogger().severe("查询当前文件夹信息失败：" + ex.getMessage());
                    }
                    sendErrorResponse(exchange, 500, "查询文件夹信息失败");
                    return;
                }
                if (currentFolder == null) {
                    sendErrorResponse(exchange, 404, "文件夹不存在或无权限");
                    return;
                }
            }

            try {
                dbLock.lock();
                String sql = "SELECT id, filename, file_type, filesize, upload_time, parent_id FROM files " +
                        "WHERE uploader_id = ? AND is_deleted = 0 AND " +
                        (folderId == null ? "parent_id IS NULL " : "parent_id = ? ") +
                        "ORDER BY CASE WHEN file_type = 'folder' THEN 0 ELSE 1 END, upload_time DESC";
                PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(sql);
                pstmt.setInt(1, userInfo.userId);
                if (folderId != null) {
                    pstmt.setInt(2, folderId);
                }
                ResultSet rs = pstmt.executeQuery();

                List<Map<String, Object>> fileList = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> file = new HashMap<>();
                    file.put("id", rs.getInt("id"));
                    file.put("filename", rs.getString("filename"));
                    file.put("fileType", rs.getString("file_type") != null ? rs.getString("file_type") : "application/octet-stream");
                    file.put("fileSize", rs.getLong("filesize"));
                    file.put("uploadTime", rs.getString("upload_time"));
                    int parentValue = rs.getInt("parent_id");
                    file.put("parentId", rs.wasNull() ? null : parentValue);
                    fileList.add(file);
                }

                Map<String, Object> response = new HashMap<>();
                response.put("files", fileList);
                try {
                    response.put("breadcrumbs", FolderService.buildBreadcrumbs(currentFolder, userInfo.userId));
                } catch (SQLException ex) {
                    if (ServerContext.getLogger() != null) {
                        ServerContext.getLogger().warning("构建面包屑失败：" + ex.getMessage());
                    }
                    response.put("breadcrumbs", Collections.emptyList());
                }
                response.put("currentFolder", currentFolder == null ? null : currentFolder.toMap());

                sendSuccessResponse(exchange, response);
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().info("用户查询文件列表：" + userInfo.username + "（文件数：" + fileList.size() + "，folderId=" + folderId + ")");
                }
            } catch (SQLException e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("查询文件列表异常：" + e.getMessage());
                }
                sendErrorResponse(exchange, 500, "服务器内部错误");
            } finally {
                dbLock.unlock();
            }
        }
    }

    public static class FileUploadHandler extends AbstractTokenHandler {
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            Map<String, String> queryParams = FileHelper.parseQueryParams(exchange.getRequestURI().getQuery());
            Integer parentId = null;
            if (queryParams.containsKey("parentId") && !queryParams.get("parentId").isBlank()) {
                try {
                    parentId = Integer.parseInt(queryParams.get("parentId"));
                } catch (NumberFormatException e) {
                    sendErrorResponse(exchange, 400, "parentId 必须是数字");
                    return;
                }
            }

            if (parentId != null) {
                try {
                    FolderService.FolderInfo targetFolder = FolderService.getFolderInfo(parentId, userInfo.userId);
                    if (targetFolder == null) {
                        sendErrorResponse(exchange, 404, "目标文件夹不存在或无权限");
                        return;
                    }
                } catch (SQLException ex) {
                    if (ServerContext.getLogger() != null) {
                        ServerContext.getLogger().severe("校验目标文件夹失败：" + ex.getMessage());
                    }
                    sendErrorResponse(exchange, 500, "校验目标文件夹失败");
                    return;
                }
            }

            String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            if (contentType == null || !contentType.startsWith("multipart/form-data")) {
                sendErrorResponse(exchange, 400, "无效的请求格式，需为multipart/form-data");
                return;
            }

            String boundary = extractBoundary(contentType);
            if (boundary == null) {
                sendErrorResponse(exchange, 400, "无法解析multipart边界");
                return;
            }

            try {
                byte[] fullBody = readRequestBody(exchange);
                if (fullBody.length == 0) {
                    sendErrorResponse(exchange, 400, "请求体为空");
                    return;
                }

                String originalFilename = extractFilename(fullBody, boundary);
                if (!FileHelper.isValidFilename(originalFilename)) {
                    sendErrorResponse(exchange, 400, "文件名不合法（含特殊字符或路径穿越）");
                    return;
                }

                byte[] fileContent = extractFileContent(fullBody, boundary);
                if (fileContent == null || fileContent.length == 0) {
                    sendErrorResponse(exchange, 400, "文件内容为空");
                    return;
                }

                if (fileContent.length > HttpFileServer.MAX_UPLOAD_SIZE) {
                    sendErrorResponse(exchange, 400, "文件过大，最大支持" + HttpFileServer.MAX_UPLOAD_SIZE / 1024 / 1024 + "MB");
                    return;
                }

                String fileExt = originalFilename.contains(".") ?
                    originalFilename.substring(originalFilename.lastIndexOf('.')) : ".bin";
                String storedFilename = System.currentTimeMillis() + "_" + UUID.randomUUID() + fileExt;
                String storedFilePath = HttpFileServer.UPLOAD_DIR + java.io.File.separator + storedFilename;
                Path filePath = Paths.get(storedFilePath);

                Files.write(filePath, fileContent);
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().info("文件写入成功：" + storedFilePath + "（大小：" + fileContent.length + "字节）");
                }

                String md5 = FileHelper.calculateFileMd5(storedFilePath);
                String mimeType = Files.probeContentType(filePath);
                if (mimeType == null) {
                    mimeType = "application/octet-stream";
                }

                dbLock.lock();
                try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                        "INSERT INTO files (filename, file_type, filepath, filesize, md5, uploader_id, parent_id) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?)", Statement.RETURN_GENERATED_KEYS)) {
                    pstmt.setString(1, originalFilename);
                    pstmt.setString(2, mimeType);
                    pstmt.setString(3, storedFilePath);
                    pstmt.setLong(4, fileContent.length);
                    pstmt.setString(5, md5);
                    pstmt.setInt(6, userInfo.userId);
                    if (parentId == null) {
                        pstmt.setNull(7, Types.INTEGER);
                    } else {
                        pstmt.setInt(7, parentId);
                    }
                    pstmt.executeUpdate();

                    int fileId = -1;
                    try (ResultSet keys = pstmt.getGeneratedKeys()) {
                        if (keys.next()) {
                            fileId = keys.getInt(1);
                        }
                    }

                    Map<String, Object> fileData = new HashMap<>();
                    fileData.put("id", fileId);
                    fileData.put("originalFilename", originalFilename);
                    fileData.put("storedFilename", storedFilename);
                    fileData.put("fileType", mimeType);
                    fileData.put("fileSize", fileContent.length);
                    fileData.put("md5", md5);
                    fileData.put("uploadTime", new Date());
                    fileData.put("parentId", parentId);

                    sendSuccessResponse(exchange, fileData);
                    if (ServerContext.getLogger() != null) {
                        ServerContext.getLogger().info("用户上传文件成功：" + userInfo.username + "（文件：" + originalFilename + "）");
                    }
                } finally {
                    dbLock.unlock();
                }

            } catch (Exception e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("文件上传异常：" + e.getMessage());
                }
                sendErrorResponse(exchange, 500, "文件上传失败：" + e.getMessage());
            }
        }

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

        private String extractFilename(byte[] fullBody, String boundary) {
            String bodyStr = new String(fullBody, StandardCharsets.UTF_8);
            String[] lines = bodyStr.split("\r\n");
            String boundaryDelimiter = "--" + boundary;

            for (int i = 0; i < lines.length; i++) {
                if (lines[i].startsWith(boundaryDelimiter) && i < lines.length - 1) {
                    for (int j = i + 1; j < lines.length; j++) {
                        if (lines[j].contains("filename=")) {
                            String[] parts = lines[j].split("filename=");
                            if (parts.length >= 2) {
                                String filename = parts[1].trim();
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

        private byte[] extractFileContent(byte[] fullBody, String boundary) {
            String boundaryDelimiter = "--" + boundary;
            String endBoundary = boundaryDelimiter + "--";
            byte[] boundaryBytes = boundaryDelimiter.getBytes(StandardCharsets.UTF_8);
            byte[] endBoundaryBytes = endBoundary.getBytes(StandardCharsets.UTF_8);
            byte[] contentStartMarker = "\r\n\r\n".getBytes(StandardCharsets.UTF_8);

            int startIndex = FileHelper.indexOf(fullBody, contentStartMarker, 0);
            if (startIndex == -1) {
                return null;
            }
            startIndex += contentStartMarker.length;

            int endIndex = FileHelper.indexOf(fullBody, endBoundaryBytes, startIndex);
            if (endIndex == -1) {
                endIndex = FileHelper.indexOf(fullBody, boundaryBytes, startIndex);
            }
            if (endIndex == -1) {
                endIndex = fullBody.length;
            } else {
                if (endIndex >= 2 && fullBody[endIndex - 2] == '\r' && fullBody[endIndex - 1] == '\n') {
                    endIndex -= 2;
                }
            }

            if (startIndex >= endIndex) {
                return null;
            }
            return Arrays.copyOfRange(fullBody, startIndex, endIndex);
        }
    }

    public static class FileDeleteHandler extends AbstractTokenHandler {
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持POST方法");
                return;
            }

            List<Integer> targetIds;
            try (BufferedReader br = new BufferedReader(new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                JsonObject req = gson.fromJson(br, JsonObject.class);
                targetIds = extractFileIds(req);
            } catch (Exception e) {
                sendErrorResponse(exchange, 400, "请求体解析失败：" + e.getMessage());
                return;
            }

            if (targetIds.isEmpty()) {
                sendErrorResponse(exchange, 400, "缺少参数：fileId 或 fileIds");
                return;
            }

            dbLock.lock();
            try {
                int deletedCount = 0;
                for (int fileId : targetIds) {
                    FileMeta meta = fetchFileMeta(fileId);
                    if (meta == null) {
                        sendErrorResponse(exchange, 404, "文件不存在或无权限：" + fileId);
                        return;
                    }
                    if (meta.isFolder()) {
                        deleteFolderRecursive(meta);
                    } else {
                        deleteFile(meta);
                    }
                    deletedCount++;
                }
                Map<String, Object> resp = new HashMap<>();
                resp.put("deleted", deletedCount);
                sendSuccessResponse(exchange, resp);
            } catch (Exception e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("删除文件异常：" + e.getMessage());
                }
                sendErrorResponse(exchange, 500, "文件删除失败：" + e.getMessage());
            } finally {
                dbLock.unlock();
            }
        }

        private List<Integer> extractFileIds(JsonObject req) {
            List<Integer> result = new ArrayList<>();
            if (req == null) {
                return result;
            }
            Set<Integer> unique = new LinkedHashSet<>();
            if (req.has("fileIds") && req.get("fileIds").isJsonArray()) {
                req.get("fileIds").getAsJsonArray().forEach(element -> {
                    try {
                        unique.add(element.getAsInt());
                    } catch (Exception ignored) {}
                });
            }
            if (req.has("fileId")) {
                try {
                    unique.add(req.get("fileId").getAsInt());
                } catch (Exception ignored) {}
            }
            result.addAll(unique);
            return result;
        }

        private FileMeta fetchFileMeta(int fileId) throws SQLException {
            try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                    "SELECT id, filename, filepath, file_type FROM files WHERE id = ? AND uploader_id = ? AND is_deleted = 0")) {
                pstmt.setInt(1, fileId);
                pstmt.setInt(2, userInfo.userId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (!rs.next()) {
                        return null;
                    }
                    return new FileMeta(
                            rs.getInt("id"),
                            rs.getString("filename"),
                            rs.getString("filepath"),
                            rs.getString("file_type"));
                }
            }
        }

        private void deleteFile(FileMeta meta) throws SQLException, IOException {
            moveFileToRecycle(meta);
            markDeleted(meta.id());
            if (ServerContext.getLogger() != null) {
                ServerContext.getLogger().info("用户删除文件（移至回收站）：" + userInfo.username + "（文件：" + meta.name() + "）");
            }
        }

        private void deleteFolderRecursive(FileMeta folder) throws SQLException, IOException {
            for (FileMeta child : fetchChildren(folder.id())) {
                if (child.isFolder()) {
                    deleteFolderRecursive(child);
                } else {
                    deleteFile(child);
                }
            }
            markDeleted(folder.id());
            if (ServerContext.getLogger() != null) {
                ServerContext.getLogger().info("用户删除文件夹（移至回收站）：" + userInfo.username + "（文件夹：" + folder.name() + "）");
            }
        }

        private List<FileMeta> fetchChildren(int folderId) throws SQLException {
            List<FileMeta> children = new ArrayList<>();
            try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                    "SELECT id, filename, filepath, file_type FROM files WHERE parent_id = ? AND uploader_id = ? AND is_deleted = 0")) {
                pstmt.setInt(1, folderId);
                pstmt.setInt(2, userInfo.userId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        children.add(new FileMeta(
                                rs.getInt("id"),
                                rs.getString("filename"),
                                rs.getString("filepath"),
                                rs.getString("file_type")));
                    }
                }
            }
            return children;
        }

        private void markDeleted(int fileId) throws SQLException {
            try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                    "UPDATE files SET is_deleted = 1, delete_time = CURRENT_TIMESTAMP WHERE id = ?")) {
                pstmt.setInt(1, fileId);
                pstmt.executeUpdate();
            }
        }

        private void moveFileToRecycle(FileMeta meta) throws IOException {
            if (meta.path() == null || meta.path().startsWith("folder://")) {
                return;
            }
            Path sourcePath = Paths.get(meta.path());
            if (!Files.exists(sourcePath)) {
                return;
            }
            Path recycleDir = Paths.get(HttpFileServer.RECYCLE_DIR);
            if (!Files.exists(recycleDir)) {
                Files.createDirectories(recycleDir);
            }
            Path targetPath = recycleDir.resolve(meta.name());
            if (Files.exists(targetPath)) {
                targetPath = recycleDir.resolve(System.currentTimeMillis() + "_" + meta.name());
            }
            Files.move(sourcePath, targetPath, StandardCopyOption.REPLACE_EXISTING);
        }

        private record FileMeta(int id, String name, String path, String type) {
            private boolean isFolder() {
                return type != null && type.equalsIgnoreCase("folder");
            }
        }
    }

    public static class FilePermanentDeleteHandler extends AbstractTokenHandler {
        private final ReentrantLock dbLock = ServerContext.getDbLock();

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
                    try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
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

                            Path path = Paths.get(filepath);
                            try {
                                if (Files.exists(path)) {
                                    Files.delete(path);
                                    if (ServerContext.getLogger() != null) {
                                        ServerContext.getLogger().info("已删除物理文件：" + filepath);
                                    }
                                } else if (ServerContext.getLogger() != null) {
                                    ServerContext.getLogger().info("物理文件不存在，跳过删除：" + filepath);
                                }
                            } catch (IOException ex) {
                                if (ServerContext.getLogger() != null) {
                                    ServerContext.getLogger().warning("删除物理文件失败：" + ex.getMessage());
                                }
                            }

                            try (PreparedStatement delStmt = ServerContext.getConnection().prepareStatement(
                                    "DELETE FROM files WHERE id = ?")) {
                                delStmt.setInt(1, fileId);
                                int affected = delStmt.executeUpdate();
                                Map<String, Object> resp = new HashMap<>();
                                resp.put("deleted", affected);
                                sendSuccessResponse(exchange, resp);
                                if (ServerContext.getLogger() != null) {
                                    ServerContext.getLogger().info("永久删除文件记录，fileId=" + fileId + ", 用户=" + userInfo.username);
                                }
                                return;
                            }
                        }
                    }
                } catch (SQLException e) {
                    if (ServerContext.getLogger() != null) {
                        ServerContext.getLogger().severe("永久删除文件异常：" + e.getMessage());
                    }
                    sendErrorResponse(exchange, 500, "永久删除失败：" + e.getMessage());
                } finally {
                    dbLock.unlock();
                }
            } catch (Exception e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("永久删除接口异常：" + e.getMessage());
                }
                sendErrorResponse(exchange, 500, "服务器内部错误");
            }
        }
    }

    public static class FileDownloadHandler extends AbstractTokenHandler {
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
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
                PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
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

                if (!Files.exists(filePath)) {
                    sendErrorResponse(exchange, 404, "文件已被删除或移动");
                    return;
                }
                if (Files.size(filePath) != fileSize) {
                    sendErrorResponse(exchange, 500, "文件大小不匹配，可能已被篡改");
                    return;
                }
                String actualMd5 = FileHelper.calculateFileMd5(filepath);
                if (!actualMd5.equals(storedMd5)) {
                    sendErrorResponse(exchange, 500, "文件内容已篡改，MD5校验失败");
                    return;
                }

                exchange.getResponseHeaders().set("Content-Type", "application/octet-stream");
                exchange.getResponseHeaders().set("Content-Length", String.valueOf(fileSize));
                String encodedFilename = URLEncoder.encode(filename, StandardCharsets.UTF_8).replace("+", "%20");
                exchange.getResponseHeaders().set("Content-Disposition",
                        "attachment; filename=\"" + encodedFilename + "\"");
                exchange.getResponseHeaders().set("Content-Transfer-Encoding", "binary");

                exchange.sendResponseHeaders(200, fileSize);

                try (BufferedInputStream in = new BufferedInputStream(Files.newInputStream(filePath));
                     BufferedOutputStream out = new BufferedOutputStream(exchange.getResponseBody())) {
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        out.write(buffer, 0, bytesRead);
                    }
                    out.flush();
                }

                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().info("用户下载文件成功：" + userInfo.username + "（文件：" + filename + "）");
                }
            } catch (Exception e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("文件下载异常：" + e.getMessage());
                }
                try {
                    sendErrorResponse(exchange, 500, "文件下载失败：" + e.getMessage());
                } catch (IllegalStateException ex) {
                    if (ServerContext.getLogger() != null) {
                        ServerContext.getLogger().warning("下载响应已发送，无法返回错误信息：" + ex.getMessage());
                    }
                }
            } finally {
                dbLock.unlock();
            }
        }
    }

    public static class FilePreviewHandler extends AbstractTokenHandler {
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
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
                PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
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

                if (!FileHelper.isTextFile(fileType, filePath)) {
                    sendErrorResponse(exchange, 403, "仅支持文本文件预览（.txt/.java/.json/.html等）");
                    return;
                }

                String content = Files.readString(filePath, StandardCharsets.UTF_8);
                String previewContent = content.substring(0, Math.min(2048, content.length()));
                boolean isTruncated = content.length() > 2048;

                Map<String, Object> previewData = new HashMap<>();
                previewData.put("filename", filename);
                previewData.put("fileSize", fileSize);
                previewData.put("content", previewContent);
                previewData.put("isTruncated", isTruncated);
                previewData.put("tip", isTruncated ? "仅显示前2KB内容，完整内容请下载" : "完整内容预览");

                sendSuccessResponse(exchange, previewData);
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().info("用户预览文件：" + userInfo.username + "（文件：" + filename + "）");
                }
            } catch (Exception e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("文件预览异常：" + e.getMessage());
                }
                sendErrorResponse(exchange, 500, "文件预览失败：" + e.getMessage());
            } finally {
                dbLock.unlock();
            }
        }
    }
}
