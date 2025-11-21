import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 文件与请求参数相关的工具方法。
 */
public final class FileHelper {
    private FileHelper() {
    }

    public static boolean isValidFilename(String filename) {
        if (filename == null || filename.isEmpty() || filename.length() > 255) {
            return false;
        }
        Pattern invalidPattern = Pattern.compile("[\\\\/:*?\"<>|]|\\.\\.");
        return !invalidPattern.matcher(filename).find();
    }

    public static String calculateFileMd5(String filePath) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        try (InputStream is = Files.newInputStream(Path.of(filePath))) {
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

    public static Map<String, String> parseQueryParams(String query) {
        Map<String, String> params = new HashMap<>();
        if (query == null || query.isEmpty()) {
            return params;
        }
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            if (pair == null || pair.isEmpty()) {
                continue;
            }
            int idx = pair.indexOf('=');
            if (idx <= 0 || idx == pair.length() - 1) {
                continue;
            }
            String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
            params.put(key, value);
        }
        return params;
    }

    public static boolean isTextFile(String fileType, Path filePath) throws IOException {
        if (fileType != null && fileType.startsWith("text/")) {
            return true;
        }
        String filename = filePath.getFileName().toString().toLowerCase();
        String[] textExtensions = {".txt", ".java", ".html", ".htm", ".css", ".js", ".json", ".xml", ".md", ".csv", ".log"};
        for (String ext : textExtensions) {
            if (filename.endsWith(ext)) {
                return true;
            }
        }
        try (InputStream in = Files.newInputStream(filePath)) {
            byte[] buffer = new byte[1024];
            int bytesRead = in.read(buffer);
            if (bytesRead <= 0) {
                return true;
            }
            int nonTextCount = 0;
            for (int i = 0; i < bytesRead; i++) {
                byte b = buffer[i];
                if (b < 9 || (b > 13 && b < 32) || b > 126) {
                    nonTextCount++;
                }
            }
            return (nonTextCount * 100.0 / bytesRead) < 10;
        }
    }

    public static int indexOf(byte[] source, byte[] target, int start) {
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
}
