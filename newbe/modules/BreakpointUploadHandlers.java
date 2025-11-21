import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

/**
 * 断点续传处理器，提供开始上传、追加分片、完成上传的三条接口。
 */
public final class BreakpointUploadHandlers {
	private static final String STATUS_UPLOADING = "UPLOADING";
	private static final String STATUS_DONE = "DONE";

	private BreakpointUploadHandlers() {
	}

	private static Path getChunkRootDir() throws IOException {
		Path chunkRoot = Paths.get(HttpFileServer.UPLOAD_DIR, "chunks");
		if (!Files.exists(chunkRoot)) {
			Files.createDirectories(chunkRoot);
		}
		return chunkRoot;
	}

	private static Path getChunkDir(String uploadId) throws IOException {
		Path chunkDir = getChunkRootDir().resolve(uploadId);
		if (!Files.exists(chunkDir)) {
			Files.createDirectories(chunkDir);
		}
		return chunkDir;
	}

	public static class StartHandler extends AbstractTokenHandler {
		private final ReentrantLock dbLock = ServerContext.getDbLock();

		@Override
		protected void handleWithAuth(HttpExchange exchange) throws IOException {
			if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
				sendErrorResponse(exchange, 405, "只支持POST方法");
				return;
			}

			JsonObject body;
			try (InputStream in = exchange.getRequestBody()) {
				body = ServerContext.getGson().fromJson(new String(in.readAllBytes(), StandardCharsets.UTF_8), JsonObject.class);
			} catch (Exception ex) {
				sendErrorResponse(exchange, 400, "请求体解析失败");
				return;
			}

			if (body == null || !body.has("fileName") || !body.has("totalSize") || !body.has("chunkSize")) {
				sendErrorResponse(exchange, 400, "缺少必要参数：fileName/totalSize/chunkSize");
				return;
			}

			String fileName = body.get("fileName").getAsString();
			long totalSize = body.get("totalSize").getAsLong();
			long chunkSize = body.get("chunkSize").getAsLong();
			if (chunkSize <= 0) {
				sendErrorResponse(exchange, 400, "chunkSize必须大于0");
				return;
			}
			if (chunkSize > HttpFileServer.MAX_UPLOAD_SIZE) {
				sendErrorResponse(exchange, 400, "chunkSize过大");
				return;
			}
			if (totalSize <= 0 || totalSize > HttpFileServer.MAX_UPLOAD_SIZE * 20) {
				sendErrorResponse(exchange, 400, "文件大小超限");
				return;
			}
			// 默认根目录；如需支持文件夹上传，请在客户端传 parentId。
			Integer parentId = body.has("parentId") && !body.get("parentId").isJsonNull()
				? body.get("parentId").getAsInt() : null;

			if (!FileHelper.isValidFilename(fileName)) {
				sendErrorResponse(exchange, 400, "文件名不合法");
				return;
			}

			String uploadId = UUID.randomUUID().toString();
			Logger logger = ServerContext.getLogger();

			try {
				getChunkDir(uploadId);
			} catch (IOException ex) {
				if (logger != null) {
					logger.severe("创建分片目录失败：" + ex.getMessage());
				}
				sendErrorResponse(exchange, 500, "创建分片目录失败");
				return;
			}

			dbLock.lock();
			try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
					"INSERT INTO upload_sessions (upload_id, user_id, file_name, total_size, uploaded_size, status, updated_at) " +
						"VALUES (?, ?, ?, ?, 0, ?, CURRENT_TIMESTAMP)")) {
				pstmt.setString(1, uploadId);
				pstmt.setInt(2, userInfo.userId);
				pstmt.setString(3, fileName);
				pstmt.setLong(4, totalSize);
				pstmt.setString(5, STATUS_UPLOADING);
				pstmt.executeUpdate();
			} catch (SQLException ex) {
				if (logger != null) {
					logger.severe("插入上传会话失败：" + ex.getMessage());
				}
				sendErrorResponse(exchange, 500, "创建上传会话失败");
				return;
			} finally {
				dbLock.unlock();
			}

			Map<String, Object> resp = new HashMap<>();
			resp.put("uploadId", uploadId);
			resp.put("fileName", fileName);
			resp.put("totalSize", totalSize);
			resp.put("parentId", parentId);
			resp.put("chunkSize", chunkSize);
			sendSuccessResponse(exchange, resp);

			if (logger != null) {
				logger.info("开始断点续传：" + userInfo.username + " -> " + uploadId + " (" + fileName + ")");
			}
		}
	}

	public static class AppendHandler extends AbstractTokenHandler {
		private final ReentrantLock dbLock = ServerContext.getDbLock();

		@Override
		protected void handleWithAuth(HttpExchange exchange) throws IOException {
			if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
				sendErrorResponse(exchange, 405, "只支持POST方法");
				return;
			}

			Map<String, String> queryParams = FileHelper.parseQueryParams(exchange.getRequestURI().getQuery());
			String uploadId = queryParams.get("uploadId");
			String chunkIndexStr = queryParams.get("chunkIndex");

			if (uploadId == null || chunkIndexStr == null) {
				sendErrorResponse(exchange, 400, "缺少参数：uploadId或chunkIndex");
				return;
			}

			int chunkIndex;
			try {
				chunkIndex = Integer.parseInt(chunkIndexStr);
			} catch (NumberFormatException ex) {
				sendErrorResponse(exchange, 400, "chunkIndex必须为整数");
				return;
			}
			if (chunkIndex < 0) {
				sendErrorResponse(exchange, 400, "chunkIndex不能为负数");
				return;
			}

			UploadSession session = loadSession(uploadId);
			if (session == null) {
				sendErrorResponse(exchange, 404, "上传会话不存在");
				return;
			}
			if (session.userId != userInfo.userId) {
				sendErrorResponse(exchange, 403, "无权操作该上传会话");
				return;
			}
			if (!STATUS_UPLOADING.equals(session.status)) {
				sendErrorResponse(exchange, 400, "上传会话状态异常");
				return;
			}

			byte[] chunkData;
			try (InputStream in = exchange.getRequestBody()) {
				chunkData = in.readAllBytes();
			}
			if (chunkData.length == 0) {
				sendErrorResponse(exchange, 400, "分片数据为空");
				return;
			}

			Path chunkPath;
			long previousSize = 0;
			try {
				chunkPath = getChunkDir(uploadId).resolve(String.format("%08d.part", chunkIndex));
				if (Files.exists(chunkPath)) {
					previousSize = Files.size(chunkPath);
				}
				try (OutputStream out = Files.newOutputStream(chunkPath,
						StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
					out.write(chunkData);
				}
			} catch (IOException ex) {
				Logger logger = ServerContext.getLogger();
				if (logger != null) {
					logger.severe("写入分片失败：" + ex.getMessage());
				}
				sendErrorResponse(exchange, 500, "写入分片失败");
				return;
			}

			long delta = chunkData.length - previousSize;
			if (delta == 0) {
				sendSuccessResponse(exchange, Map.of("uploadedSize", session.uploadedSize));
				return;
			}

			dbLock.lock();
			try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
					"UPDATE upload_sessions SET uploaded_size = uploaded_size + ?, updated_at = CURRENT_TIMESTAMP " +
						"WHERE upload_id = ? AND status = ?")) {
				pstmt.setLong(1, delta);
				pstmt.setString(2, uploadId);
				pstmt.setString(3, STATUS_UPLOADING);
				int affected = pstmt.executeUpdate();
				if (affected == 0) {
					sendErrorResponse(exchange, 409, "上传会话已完成或不存在");
					return;
				}
			} catch (SQLException ex) {
				Logger logger = ServerContext.getLogger();
				if (logger != null) {
					logger.severe("更新会话进度失败：" + ex.getMessage());
				}
				sendErrorResponse(exchange, 500, "更新进度失败");
				return;
			} finally {
				dbLock.unlock();
			}

			UploadSession refreshed = loadSession(uploadId);
			if (refreshed == null) {
				sendErrorResponse(exchange, 500, "查询会话失败");
				return;
			}
			if (refreshed.uploadedSize > refreshed.totalSize) {
				sendErrorResponse(exchange, 409, "上传大小超出总量");
				return;
			}

			Map<String, Object> resp = new HashMap<>();
			resp.put("uploadedSize", refreshed.uploadedSize);
			resp.put("totalSize", refreshed.totalSize);
			resp.put("chunkIndex", chunkIndex);
			sendSuccessResponse(exchange, resp);
		}

		private UploadSession loadSession(String uploadId) {
			try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
					"SELECT upload_id, user_id, file_name, total_size, uploaded_size, status FROM upload_sessions WHERE upload_id = ?")) {
				pstmt.setString(1, uploadId);
				try (ResultSet rs = pstmt.executeQuery()) {
					if (!rs.next()) {
						return null;
					}
					return new UploadSession(
						rs.getString("upload_id"),
						rs.getInt("user_id"),
						rs.getString("file_name"),
						rs.getLong("total_size"),
						rs.getLong("uploaded_size"),
						rs.getString("status"));
				}
			} catch (SQLException ex) {
				Logger logger = ServerContext.getLogger();
				if (logger != null) {
					logger.severe("查询上传会话失败：" + ex.getMessage());
				}
				return null;
			}
		}
	}

	public static class CompleteHandler extends AbstractTokenHandler {
		private final ReentrantLock dbLock = ServerContext.getDbLock();

		@Override
		protected void handleWithAuth(HttpExchange exchange) throws IOException {
			if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
				sendErrorResponse(exchange, 405, "只支持POST方法");
				return;
			}

			JsonObject body;
			try (InputStream in = exchange.getRequestBody()) {
				body = ServerContext.getGson().fromJson(new String(in.readAllBytes(), StandardCharsets.UTF_8), JsonObject.class);
			} catch (Exception ex) {
				sendErrorResponse(exchange, 400, "请求体解析失败");
				return;
			}

			if (body == null || !body.has("uploadId")) {
				sendErrorResponse(exchange, 400, "缺少参数：uploadId");
				return;
			}

			String uploadId = body.get("uploadId").getAsString();
			Integer parentId = body.has("parentId") && !body.get("parentId").isJsonNull()
				? body.get("parentId").getAsInt() : null;

			UploadSession session = fetchSession(uploadId);
			if (session == null) {
				sendErrorResponse(exchange, 404, "上传会话不存在");
				return;
			}
			if (session.userId != userInfo.userId) {
				sendErrorResponse(exchange, 403, "无权操作该上传会话");
				return;
			}
			if (!STATUS_UPLOADING.equals(session.status) && !STATUS_DONE.equals(session.status)) {
				sendErrorResponse(exchange, 400, "上传状态异常");
				return;
			}

			Path chunkDir;
			try {
				chunkDir = getChunkDir(uploadId);
			} catch (IOException ex) {
				sendErrorResponse(exchange, 500, "读取分片目录失败");
				return;
			}

			TreeMap<Integer, Path> chunkFiles = new TreeMap<>();
			try {
				Files.list(chunkDir).filter(Files::isRegularFile).forEach(path -> {
					String name = path.getFileName().toString();
					if (name.endsWith(".part")) {
						try {
							int idx = Integer.parseInt(name.replace(".part", ""));
							chunkFiles.put(idx, path);
						} catch (NumberFormatException ignored) {
						}
					}
				});
			} catch (IOException ex) {
				sendErrorResponse(exchange, 500, "读取分片列表失败");
				return;
			}

			if (chunkFiles.isEmpty()) {
				sendErrorResponse(exchange, 400, "未找到任何分片");
				return;
			}

			long mergedSize = 0;
			for (Path chunk : chunkFiles.values()) {
				try {
					mergedSize += Files.size(chunk);
				} catch (IOException ex) {
					sendErrorResponse(exchange, 500, "读取分片大小失败");
					return;
				}
			}

			if (mergedSize != session.totalSize) {
				sendErrorResponse(exchange, 409, "分片大小与总大小不一致");
				return;
			}

			Path finalDir = Paths.get(HttpFileServer.UPLOAD_DIR);
			if (!Files.exists(finalDir)) {
				Files.createDirectories(finalDir);
			}

			String extension = session.fileName.contains(".")
				? session.fileName.substring(session.fileName.lastIndexOf('.'))
				: ""
				;
			String storedFilename = System.currentTimeMillis() + "_" + UUID.randomUUID() + extension;
			Path finalPath = finalDir.resolve(storedFilename);

			try (OutputStream finalOut = Files.newOutputStream(finalPath, StandardOpenOption.CREATE_NEW)) {
				for (Path chunk : chunkFiles.values()) {
					Files.copy(chunk, finalOut);
				}
			} catch (IOException ex) {
				sendErrorResponse(exchange, 500, "合并分片失败");
				return;
			}

			String md5;
			try {
				md5 = FileHelper.calculateFileMd5(finalPath.toString());
			} catch (Exception ex) {
				sendErrorResponse(exchange, 500, "计算文件摘要失败");
				return;
			}

			String mimeType = Files.probeContentType(finalPath);
			if (mimeType == null) {
				mimeType = "application/octet-stream";
			}

			dbLock.lock();
			int fileId = -1;
			try (PreparedStatement insertFile = ServerContext.getConnection().prepareStatement(
					"INSERT INTO files (filename, file_type, filepath, filesize, md5, uploader_id, parent_id) " +
						"VALUES (?, ?, ?, ?, ?, ?, ?)", PreparedStatement.RETURN_GENERATED_KEYS);
				 PreparedStatement updateSession = ServerContext.getConnection().prepareStatement(
					"UPDATE upload_sessions SET status = ?, uploaded_size = total_size, updated_at = CURRENT_TIMESTAMP WHERE upload_id = ?")) {
				insertFile.setString(1, session.fileName);
				insertFile.setString(2, mimeType);
				insertFile.setString(3, finalPath.toString());
				insertFile.setLong(4, mergedSize);
				insertFile.setString(5, md5);
				insertFile.setInt(6, userInfo.userId);
				if (parentId == null) {
					insertFile.setNull(7, java.sql.Types.INTEGER);
				} else {
					insertFile.setInt(7, parentId);
				}
				insertFile.executeUpdate();

				try (ResultSet keys = insertFile.getGeneratedKeys()) {
					if (keys.next()) {
						fileId = keys.getInt(1);
					}
				}

				updateSession.setString(1, STATUS_DONE);
				updateSession.setString(2, uploadId);
				updateSession.executeUpdate();
			} catch (SQLException ex) {
				Logger logger = ServerContext.getLogger();
				if (logger != null) {
					logger.severe("合并完成时写数据库失败：" + ex.getMessage());
				}
				sendErrorResponse(exchange, 500, "写入数据库失败");
				return;
			} finally {
				dbLock.unlock();
			}

			try {
				Files.walk(chunkDir)
					.sorted(Comparator.reverseOrder())
					.forEach(path -> {
						try {
							Files.deleteIfExists(path);
						} catch (IOException ignored) {
						}
					});
			} catch (IOException ignored) {
			}

			Map<String, Object> resp = new HashMap<>();
			resp.put("fileId", fileId);
			resp.put("fileName", session.fileName);
			resp.put("fileSize", mergedSize);
			resp.put("md5", md5);
			resp.put("storedPath", finalPath.toString());
			sendSuccessResponse(exchange, resp);
		}

		private UploadSession fetchSession(String uploadId) {
			try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
					"SELECT upload_id, user_id, file_name, total_size, uploaded_size, status FROM upload_sessions WHERE upload_id = ?")) {
				pstmt.setString(1, uploadId);
				try (ResultSet rs = pstmt.executeQuery()) {
					if (!rs.next()) {
						return null;
					}
					return new UploadSession(
						rs.getString("upload_id"),
						rs.getInt("user_id"),
						rs.getString("file_name"),
						rs.getLong("total_size"),
						rs.getLong("uploaded_size"),
						rs.getString("status"));
				}
			} catch (SQLException ex) {
				Logger logger = ServerContext.getLogger();
				if (logger != null) {
					logger.severe("查询上传会话失败：" + ex.getMessage());
				}
				return null;
			}
		}
	}

	private record UploadSession(String uploadId, int userId, String fileName, long totalSize, long uploadedSize, String status) {
	}
}
