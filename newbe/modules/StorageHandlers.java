import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 存储统计相关 Handler。
 */
public final class StorageHandlers {
    private StorageHandlers() {}

    public static class UsageHandler extends AbstractTokenHandler {
        private static final long DEFAULT_QUOTA_BYTES = 10L * 1024 * 1024 * 1024;
        private final ReentrantLock dbLock = ServerContext.getDbLock();

        @Override
        protected void handleWithAuth(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "只支持GET方法");
                return;
            }

            long usedBytes = 0L;
            long recycleBytes = 0L;
            int activeFiles = 0;
            int recycleFiles = 0;
            try {
                dbLock.lock();
                try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                        "SELECT is_deleted, COALESCE(SUM(filesize), 0) AS total_bytes, COUNT(*) AS total_files " +
                        "FROM files WHERE uploader_id = ? GROUP BY is_deleted")) {
                    pstmt.setInt(1, userInfo.userId);
                    try (ResultSet rs = pstmt.executeQuery()) {
                        while (rs.next()) {
                            int deleted = rs.getInt("is_deleted");
                            long bytes = rs.getLong("total_bytes");
                            int count = rs.getInt("total_files");
                            if (deleted == 1) {
                                recycleBytes = bytes;
                                recycleFiles = count;
                            } else {
                                usedBytes = bytes;
                                activeFiles = count;
                            }
                        }
                    }
                }
            } catch (SQLException e) {
                if (ServerContext.getLogger() != null) {
                    ServerContext.getLogger().severe("计算存储使用情况失败：" + e.getMessage());
                }
                sendErrorResponse(exchange, 500, "查询存储使用情况失败");
                return;
            } finally {
                dbLock.unlock();
            }

            long quotaBytes = DEFAULT_QUOTA_BYTES;
            double usedPercent = quotaBytes > 0 ? (double) usedBytes / quotaBytes : 0;
            Map<String, Object> payload = new HashMap<>();
            payload.put("usedBytes", usedBytes);
            payload.put("recycleBytes", recycleBytes);
            payload.put("totalBytes", quotaBytes);
            payload.put("availableBytes", Math.max(quotaBytes - usedBytes, 0));
            payload.put("usedPercent", usedPercent);
            payload.put("activeFileCount", activeFiles);
            payload.put("recycleFileCount", recycleFiles);

            sendSuccessResponse(exchange, payload);
            if (ServerContext.getLogger() != null) {
                ServerContext.getLogger().info(String.format(
                        "用户查询存储使用情况：%s（used=%dB, recycle=%dB）",
                        userInfo.username,
                        usedBytes,
                        recycleBytes));
            }
        }
    }
}
