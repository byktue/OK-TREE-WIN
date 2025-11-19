import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * 密码和 JWT 相关的安全工具。
 */
public final class SecurityUtils {
    private static final int SALT_LENGTH = 16;
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;
    private static final String JWT_SECRET = System.getenv("JWT_SECRET") != null ?
        System.getenv("JWT_SECRET") : "x8V2#zQ9!pL7@wK3$rT5*yB1&mN4%vF6^gH8(jU0)tR2";
    private static final long JWT_EXPIRE = 24 * 60 * 60 * 1000;
    private static final SecretKey JWT_KEY = Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));

    private SecurityUtils() {
    }

    public static String generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    public static String encryptPassword(String password, String salt) {
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
            Logger logger = ServerContext.getLogger();
            if (logger != null) {
                logger.severe("密码加密失败：" + e.getMessage());
            }
            throw new RuntimeException("密码加密异常", e);
        }
    }

    public static boolean verifyPassword(String inputPwd, String storedPwd, String salt) {
        return encryptPassword(inputPwd, salt).equals(storedPwd);
    }

    public static String generateToken(int userId, String username, boolean isAdmin, boolean isMember) {
        return Jwts.builder()
            .id(UUID.randomUUID().toString())
            .subject(String.valueOf(userId))
            .claim("username", username)
            .claim("isAdmin", isAdmin)
            .claim("isMember", isMember)
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + JWT_EXPIRE))
            .signWith(JWT_KEY, SignatureAlgorithm.HS256)
            .compact();
    }

    public static UserTokenInfo parseToken(String token) {
        Logger logger = ServerContext.getLogger();
        try {
            Claims claims = Jwts.parser()
                .verifyWith(JWT_KEY)
                .build()
                .parseSignedClaims(token)
                .getPayload();

            if (claims.getExpiration().before(new Date())) {
                if (logger != null) {
                    logger.warning("Token已过期：用户ID=" + claims.getSubject());
                }
                return null;
            }

            return new UserTokenInfo(
                Integer.parseInt(claims.getSubject()),
                claims.get("username", String.class),
                claims.get("isAdmin", Boolean.class),
                claims.get("isMember", Boolean.class)
            );
        } catch (ExpiredJwtException e) {
            if (logger != null) {
                logger.warning("Token过期：" + e.getMessage());
            }
        } catch (MalformedJwtException e) {
            if (logger != null) {
                logger.warning("Token格式错误：" + e.getMessage());
            }
        } catch (io.jsonwebtoken.SignatureException e) {
            if (logger != null) {
                logger.warning("Token签名错误：" + e.getMessage());
            }
        } catch (IllegalArgumentException e) {
            if (logger != null) {
                logger.warning("Token为空：" + e.getMessage());
            }
        } catch (JwtException e) {
            if (logger != null) {
                logger.warning("Token无效：" + e.getMessage());
            }
        }
        return null;
    }
}
