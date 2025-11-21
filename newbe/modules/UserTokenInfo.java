/**
 * JWT 解析后的用户信息。
 */
public class UserTokenInfo {
    public final int userId;
    public final String username;
    public final boolean isAdmin;
    public final boolean isMember;

    public UserTokenInfo(int userId, String username, boolean isAdmin, boolean isMember) {
        this.userId = userId;
        this.username = username;
        this.isAdmin = isAdmin;
        this.isMember = isMember;
    }

    public boolean isAdmin() {
        return isAdmin;
    }

    public boolean isMember() {
        return isMember;
    }
}
