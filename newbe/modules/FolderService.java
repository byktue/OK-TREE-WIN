import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 文件夹相关的查询与面包屑构建。
 */
public final class FolderService {
    private FolderService() {
    }

    public static FolderInfo getFolderInfo(int folderId, int ownerId) throws SQLException {
        ReentrantLock lock = ServerContext.getDbLock();
        lock.lock();
        try (PreparedStatement pstmt = ServerContext.getConnection().prepareStatement(
                "SELECT id, filename, parent_id FROM files WHERE id = ? AND uploader_id = ? AND is_deleted = 0 AND file_type = 'folder'")) {
            pstmt.setInt(1, folderId);
            pstmt.setInt(2, ownerId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    Integer parentId = rs.getInt("parent_id");
                    if (rs.wasNull()) {
                        parentId = null;
                    }
                    return new FolderInfo(rs.getInt("id"), rs.getString("filename"), parentId);
                }
            }
            return null;
        } finally {
            lock.unlock();
        }
    }

    public static List<Map<String, Object>> buildBreadcrumbs(FolderInfo targetFolder, int ownerId) throws SQLException {
        List<Map<String, Object>> breadcrumbs = new ArrayList<>();
        Map<String, Object> root = new HashMap<>();
        root.put("id", null);
        root.put("name", "全部文件");
        breadcrumbs.add(root);

        if (targetFolder == null) {
            return breadcrumbs;
        }

        Deque<FolderInfo> stack = new ArrayDeque<>();
        FolderInfo cursor = targetFolder;
        int guard = 0;
        while (cursor != null && guard < 100) {
            stack.push(cursor);
            if (cursor.parentId() == null) {
                break;
            }
            cursor = getFolderInfo(cursor.parentId(), ownerId);
            guard++;
        }

        while (!stack.isEmpty()) {
            breadcrumbs.add(stack.pop().toMap());
        }
        return breadcrumbs;
    }

    public record FolderInfo(int id, String name, Integer parentId) {
        public Map<String, Object> toMap() {
            Map<String, Object> data = new HashMap<>();
            data.put("id", id);
            data.put("name", name);
            data.put("parentId", parentId);
            return data;
        }
    }
}
