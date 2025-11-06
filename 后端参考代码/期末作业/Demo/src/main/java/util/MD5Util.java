package util;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Util {
    /**
     * 计算指定文件的 MD5 校验和
     * @param filePath 文件路径
     * @return MD5 字符串（小写十六进制），失败返回 null
     */
    public static String calculateMD5(String filePath) {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                md.update(buffer, 0, bytesRead);
            }
            byte[] digest = md.digest();
            StringBuilder hexString = new StringBuilder();
            for (byte b : digest) {
                hexString.append(String.format("%02x", b & 0xFF));
            }
            return hexString.toString();
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 判断两个文件内容是否相同（通过 MD5 比较）
     * @param filePath1 第一个文件路径
     * @param filePath2 第二个文件路径
     * @return true 相同，false 不同或异常
     */
    public static boolean isSameFile(String filePath1, String filePath2) {
        String md5_1 = calculateMD5(filePath1);
        String md5_2 = calculateMD5(filePath2);
        return md5_1 != null && md5_1.equals(md5_2);
    }
}
