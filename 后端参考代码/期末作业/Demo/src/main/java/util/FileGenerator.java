package util;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Random;

public class FileGenerator {

    private static final int MB_10 = 10 * 1024 * 1024; // 100MB
    private static final int MB_1 = 1024 * 1024;   // 10MB

    /**
     * 生成必要的测试文件
     */
    public static void generateFile() {
        // 生成100MB文件
        generateRandomFile("src/main/java/local/file10MB", MB_10);
        // 生成10MB文件
        generateRandomFile("src/main/java/local/file1MB", MB_1);
        generateRandomFile("src/main/java/cloud/file1MB", MB_1);
    }

    public static void generateRandomFile(String filePath, int sizeInBytes) {
        Random random = new Random();
        byte[] data = new byte[1024];
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            int bytesWritten = 0;
            while (bytesWritten < sizeInBytes) {
                random.nextBytes(data);
                int remainingBytes = sizeInBytes - bytesWritten;
                int bytesToWrite = Math.min(data.length, remainingBytes);
                fos.write(data, 0, bytesToWrite);
                bytesWritten += bytesToWrite;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
