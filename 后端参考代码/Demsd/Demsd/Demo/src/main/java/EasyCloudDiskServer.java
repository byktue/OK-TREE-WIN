import util.MD5Util;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.*;
import java.util.concurrent.*;

// ============================= SERVER =============================
public class EasyCloudDiskServer {
    private static final int PORT = 8888;
    private static final String STORAGE_DIR = "src/main/java/cloud/";

    public void start() {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server started on port " + PORT);
            Files.createDirectories(Paths.get(STORAGE_DIR));

            while (true) {
                Socket client = serverSocket.accept();
                new Thread(new ClientHandler(client)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static class ClientHandler implements Runnable {
        private final Socket client;
        private static final Object fileLock = new Object();

        ClientHandler(Socket client) {
            this.client = client;
        }

        public void run() {
            try (DataInputStream dis = new DataInputStream(new BufferedInputStream(client.getInputStream()));
                 DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(client.getOutputStream()))) {

                String action = dis.readUTF();

                switch (action) {
                    case "UPLOAD":
                        handleUpload(dis, dos);
                        break;
                    case "UPLOAD_BLOCK":
                        handleUploadBlock(dis, dos);
                        break;
                    case "DOWNLOAD":
                        handleDownload(dis, dos);
                        break;
                    case "LIST_FILES":
                        handleListFiles(dis, dos);
                        break;
                    case "BATCH_UPLOAD":
                        handleBatchUpload(dis, dos);
                        break;
                    case "BATCH_DOWNLOAD":
                        handleBatchDownload(dis, dos);
                        break;
                    default:
                        System.err.println("Unknown action: " + action);
                        dos.writeUTF("ERROR: Unknown action");
                        dos.flush();
                }
            } catch (IOException e) {
                System.err.println("Error handling client: " + e.getMessage());
                e.printStackTrace();
            } finally {
                try {
                    client.close();
                } catch (IOException e) {
                    System.err.println("Error closing client socket: " + e.getMessage());
                }
            }
        }

        private void handleListFiles(DataInputStream dis, DataOutputStream dos) throws IOException {
            String path = dis.readUTF();
            File dir = new File(STORAGE_DIR + path);
            
            // 发送初始响应
            dos.writeUTF("OK");
            
            // 获取目录下所有文件
            File[] files = dir.exists() && dir.isDirectory() ? dir.listFiles() : new File[0];
            
            // 发送文件数量
            dos.writeInt(files != null ? files.length : 0);
            dos.flush();
            
            if (files != null) {
                for (File file : files) {
                    dos.writeUTF(file.getName());
                    dos.writeLong(file.length());
                    dos.writeBoolean(file.isDirectory());
                    String md5 = file.isDirectory() ? "" : MD5Util.calculateMD5(file.getPath());
                    dos.writeUTF(md5 != null ? md5 : "");
                    dos.flush();
                }
            }
        }

        private void handleBatchUpload(DataInputStream dis, DataOutputStream dos) throws IOException {
            int fileCount = dis.readInt();
            for (int i = 0; i < fileCount; i++) {
                String fileName = dis.readUTF();
                long fileSize = dis.readLong();
                String expectedMD5 = dis.readUTF();
                
                File targetFile = new File(STORAGE_DIR + fileName);
                targetFile.getParentFile().mkdirs();

                // 创建临时文件
                File tempFile = new File(targetFile.getAbsolutePath() + ".tmp");
                try (FileOutputStream fos = new FileOutputStream(tempFile)) {
                    byte[] buffer = new byte[4096];
                    int read;
                    long remaining = fileSize;
                    while (remaining > 0 && (read = dis.read(buffer, 0, (int) Math.min(buffer.length, remaining))) != -1) {
                        fos.write(buffer, 0, read);
                        remaining -= read;
                    }
                }

                // 验证MD5
                String actualMD5 = MD5Util.calculateMD5(tempFile.getPath());
                if (actualMD5 != null && actualMD5.equals(expectedMD5)) {
                    // 验证成功，重命名文件
                    if (targetFile.exists()) {
                        targetFile.delete();
                    }
                    tempFile.renameTo(targetFile);
                    dos.writeUTF("OK");
                } else {
                    // 验证失败，删除临时文件
                    tempFile.delete();
                    dos.writeUTF("ERROR: MD5 verification failed");
                }
                dos.flush();
            }
        }

        private void handleBatchDownload(DataInputStream dis, DataOutputStream dos) throws IOException {
            int fileCount = dis.readInt();
            for (int i = 0; i < fileCount; i++) {
                String fileName = dis.readUTF();
                File file = new File(STORAGE_DIR + fileName);

                if (!file.exists()) {
                    dos.writeUTF("NOT_FOUND");
                    dos.flush();
                    continue;
                }

                // 计算MD5
                String md5 = MD5Util.calculateMD5(file.getPath());
                if (md5 == null) {
                    dos.writeUTF("ERROR: Failed to calculate MD5");
                    dos.flush();
                    continue;
                }

                dos.writeUTF("OK");
                dos.writeLong(file.length());
                dos.writeUTF(md5);
                dos.flush();

                try (FileInputStream fis = new FileInputStream(file)) {
                    byte[] buffer = new byte[4096];
                    int read;
                    while ((read = fis.read(buffer)) != -1) {
                        dos.write(buffer, 0, read);
                    }
                    dos.flush();
                }
            }
        }

        private void handleUploadBlock(DataInputStream dis, DataOutputStream dos) throws IOException {
            String fileName = dis.readUTF();

            if (fileName == null || fileName.trim().isEmpty()) {
                dos.writeUTF("ERROR: Empty filename");
                dos.flush();
                return;
            }

            int blockIdx = dis.readInt();
            long offset = dis.readLong();
            int size = dis.readInt();

            System.out.printf("Block info - File: %s, Index: %d, Offset: %d, Size: %d%n", 
                            fileName, blockIdx, offset, size);

            File targetFile = new File(STORAGE_DIR + fileName);
            targetFile.getParentFile().mkdirs();

            byte[] block = new byte[size];
            int bytesRead = dis.read(block);
            
            if (bytesRead != size) {
                System.err.printf("Block size mismatch - Expected: %d, Read: %d%n", size, bytesRead);
                dos.writeUTF("ERROR: Block size mismatch");
                dos.flush();
                return;
            }

            synchronized (fileLock) {
                try (RandomAccessFile raf = new RandomAccessFile(targetFile, "rw")) {
                    raf.seek(offset);
                    raf.write(block);
                }
            }

            dos.writeUTF("BLOCK_OK");
            dos.flush();
            System.out.println("Block " + blockIdx + " for file " + fileName + " processed successfully");
        }

        private void handleUpload(DataInputStream dis, DataOutputStream dos) throws IOException {
            String fileName = dis.readUTF();
            long fileSize = dis.readLong();
            File targetFile = new File(STORAGE_DIR + fileName);
            targetFile.getParentFile().mkdirs();

            try (FileOutputStream fos = new FileOutputStream(targetFile)) {
                byte[] buffer = new byte[4096];
                int read;
                long remaining = fileSize;
                while (remaining > 0 && (read = dis.read(buffer, 0, (int) Math.min(buffer.length, remaining))) != -1) {
                    fos.write(buffer, 0, read);
                    remaining -= read;
                }
            }

            dos.writeUTF("OK");
            dos.flush();
        }

        private void handleDownload(DataInputStream dis, DataOutputStream dos) throws IOException {
            String fileName = dis.readUTF();
            File file = new File(STORAGE_DIR + fileName);

            if (!file.exists()) {
                dos.writeUTF("NOT_FOUND");
                dos.flush();
                return;
            }

            dos.writeUTF("OK");
            dos.writeLong(file.length());
            dos.flush();

            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] buffer = new byte[4096];
                int read;
                while ((read = fis.read(buffer)) != -1) {
                    dos.write(buffer, 0, read);
                }
                dos.flush();
            }
        }
    }
}