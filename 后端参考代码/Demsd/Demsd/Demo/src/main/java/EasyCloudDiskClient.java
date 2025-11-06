import util.MD5Util;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.*;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
public class EasyCloudDiskClient {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 8888;

    public void start() {
        // 可以加入命令行或图形界面交互逻辑
    }

    public void uploadFileSingleThread(String localFilePath, String remoteFilePath) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
             DataInputStream dis = new DataInputStream(socket.getInputStream());
             FileInputStream fis = new FileInputStream(localFilePath)) {

            File file = new File(localFilePath);
            dos.writeUTF("UPLOAD");
            dos.writeUTF(remoteFilePath);
            dos.writeLong(file.length());
            byte[] buffer = new byte[4096];
            int read;
            while ((read = fis.read(buffer)) != -1) {
                dos.write(buffer, 0, read);
            }

            String result = dis.readUTF();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void uploadFileMultiThread(String localFilePath, String remoteFilePath) {
        int threadCount = 4;
        File file = new File(localFilePath);
        long fileLength = file.length();
        long chunkSize = fileLength / threadCount;

        // 使用 CountDownLatch 等待所有块上传完成
        CountDownLatch latch = new CountDownLatch(threadCount);
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        for (int i = 0; i < threadCount; i++) {
            final int blockIndex = i;
            final long start = i * chunkSize;
            final long end = (i == threadCount - 1) ? fileLength : (start + chunkSize);
            final int blockSize = (int)(end - start);

            executor.submit(() -> {
                try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
                     DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
                     DataInputStream dis = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
                     RandomAccessFile raf = new RandomAccessFile(file, "r")) {

                    // 准备数据
                    byte[] buffer = new byte[blockSize];
                    raf.seek(start);
                    raf.readFully(buffer);

                    // 发送数据
                    synchronized (dos) {
                        dos.writeUTF("UPLOAD_BLOCK");
                        dos.writeUTF(remoteFilePath);     // 上传目标文件名
                        dos.writeInt(blockIndex);         // 分块编号
                        dos.writeLong(start);             // 偏移量
                        dos.writeInt(blockSize);          // 块大小
                        dos.write(buffer);                // 块数据
                        dos.flush();                      // 确保数据被发送
                    }

                    // 等待服务器响应
                    String ack = dis.readUTF();
                    if (!"BLOCK_OK".equals(ack)) {
                        System.err.println("Block " + blockIndex + " upload failed. Server response: " + ack);
                    } else {
                        System.out.println("Block " + blockIndex + " uploaded successfully.");
                    }
                } catch (IOException e) {
                    System.err.println("Error uploading block " + blockIndex + ": " + e.getMessage());
                    e.printStackTrace();
                } finally {
                    latch.countDown();
                }
            });
        }

        executor.shutdown();
        try {
            // 等待所有块上传完成或超时
            if (!latch.await(10, TimeUnit.MINUTES)) {
                System.err.println("Upload timeout - some blocks may not have been uploaded");
            }
            // 等待线程池关闭
            if (!executor.awaitTermination(1, TimeUnit.MINUTES)) {
                System.err.println("Thread pool did not terminate properly");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("Upload interrupted: " + e.getMessage());
        }

    }



    public void downloadFile(String remoteFilePath, String localFilePath) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
             DataInputStream dis = new DataInputStream(socket.getInputStream());
             FileOutputStream fos = new FileOutputStream(localFilePath)) {

            dos.writeUTF("DOWNLOAD");
            dos.writeUTF(remoteFilePath);

            String status = dis.readUTF();
            if ("NOT_FOUND".equals(status)) {
                System.out.println("File not found on server.");


                return;
            }

            long fileSize = dis.readLong();
            byte[] buffer = new byte[4096];
            int read;
            long remaining = fileSize;
            while (remaining > 0 && (read = dis.read(buffer, 0, (int) Math.min(buffer.length, remaining))) != -1) {
                fos.write(buffer, 0, read);
                remaining -= read;
            }


        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void uploadDirectory(String localDirPath, String remoteBasePath) {
        File baseDir = new File(localDirPath);
        if (!baseDir.exists() || !baseDir.isDirectory()) {
            System.out.println("无效的文件夹路径！");
            return;
        }

        List<File> allFiles = listAllFiles(baseDir);
        for (File file : allFiles) {
            // 生成相对路径（如 subdir/file.txt）
            String relativePath = baseDir.toPath().relativize(file.toPath()).toString().replace("\\", "/");
            String remotePath = remoteBasePath + "/" + relativePath;
            uploadFileSingleThread(file.getAbsolutePath(), remotePath);
        }

        System.out.println("文件夹上传完成。");
    }

    private List<File> listAllFiles(File folder) {
        List<File> files = new ArrayList<>();
        File[] list = folder.listFiles();
        if (list != null) {
            for (File f : list) {
                if (f.isDirectory()) {
                    files.addAll(listAllFiles(f));
                } else {
                    files.add(f);
                }
            }
        }
        return files;
    }

    public void listFiles(String remotePath) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
             DataInputStream dis = new DataInputStream(new BufferedInputStream(socket.getInputStream()))) {

            // 发送请求
            dos.writeUTF("LIST_FILES");
            dos.writeUTF(remotePath);
            dos.flush();

            // 读取服务器响应
            String response = dis.readUTF();
            if (!"OK".equals(response)) {
                System.err.println("获取目录列表失败: " + response);
                return;
            }

            // 读取文件数量
            int fileCount = dis.readInt();
            if (fileCount == 0) {
                System.out.println("目录为空: " + remotePath);
                return;
            }

            // 打印表头
            System.out.println("\n目录列表: " + remotePath);
            System.out.println("文件总数: " + fileCount);
            System.out.println("----------------------------------------");
            System.out.printf("%-5s %-30s %-15s %s%n", "类型", "文件名", "大小", "MD5值");
            System.out.println("----------------------------------------");
            
            // 读取每个文件的信息
            for (int i = 0; i < fileCount; i++) {
                String fileName = dis.readUTF();
                long fileSize = dis.readLong();
                boolean isDirectory = dis.readBoolean();
                String md5 = dis.readUTF();
                
                System.out.printf("%-5s %-30s %-15s %s%n",
                    isDirectory ? "目录" : "文件",
                    fileName,
                    isDirectory ? "" : String.format("%d 字节", fileSize),
                    isDirectory ? "" : md5);
            }
            System.out.println("----------------------------------------");

        } catch (IOException e) {
            System.err.println("获取目录列表时发生错误: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void batchUpload(List<String> localFilePaths, String remoteBasePath) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
             DataInputStream dis = new DataInputStream(socket.getInputStream())) {

            dos.writeUTF("BATCH_UPLOAD");
            dos.writeInt(localFilePaths.size());
            dos.flush();

            for (String localFilePath : localFilePaths) {
                File file = new File(localFilePath);
                if (!file.exists()) {
                    System.err.println("File not found: " + localFilePath);
                    continue;
                }

                // 计算相对路径
                String relativePath = new File(localFilePath).getName();
                String remoteFilePath = remoteBasePath + "/" + relativePath;

                // 计算MD5
                String md5 = MD5Util.calculateMD5(localFilePath);
                if (md5 == null) {
                    System.err.println("Failed to calculate MD5 for: " + localFilePath);
                    continue;
                }

                // 发送文件信息
                dos.writeUTF(remoteFilePath);
                dos.writeLong(file.length());
                dos.writeUTF(md5);
                dos.flush();

                // 发送文件内容
                try (FileInputStream fis = new FileInputStream(file)) {
                    byte[] buffer = new byte[4096];
                    int read;
                    while ((read = fis.read(buffer)) != -1) {
                        dos.write(buffer, 0, read);
                    }
                    dos.flush();
                }

                // 等待服务器响应
                String response = dis.readUTF();
                if ("OK".equals(response)) {
                    System.out.println("Successfully uploaded: " + remoteFilePath);
                } else {
                    System.err.println("Failed to upload " + remoteFilePath + ": " + response);
                }
            }

        } catch (IOException e) {
            System.err.println("Error in batch upload: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void batchDownload(List<String> remoteFilePaths, String localBasePath) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
             DataInputStream dis = new DataInputStream(socket.getInputStream())) {

            dos.writeUTF("BATCH_DOWNLOAD");
            dos.writeInt(remoteFilePaths.size());
            dos.flush();

            for (String remoteFilePath : remoteFilePaths) {
                // 发送文件路径
                dos.writeUTF(remoteFilePath);
                dos.flush();

                // 接收服务器响应
                String status = dis.readUTF();
                if ("NOT_FOUND".equals(status)) {
                    System.err.println("File not found on server: " + remoteFilePath);
                    continue;
                } else if (status.startsWith("ERROR")) {
                    System.err.println("Error downloading " + remoteFilePath + ": " + status);
                    continue;
                }

                // 接收文件信息
                long fileSize = dis.readLong();
                String expectedMD5 = dis.readUTF();

                // 创建本地文件
                String localFilePath = localBasePath + "/" + new File(remoteFilePath).getName();
                File localFile = new File(localFilePath);
                localFile.getParentFile().mkdirs();

                // 创建临时文件
                File tempFile = new File(localFilePath + ".tmp");
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
                    if (localFile.exists()) {
                        localFile.delete();
                    }
                    tempFile.renameTo(localFile);
                    System.out.println("Successfully downloaded: " + localFilePath);
                } else {
                    // 验证失败，删除临时文件
                    tempFile.delete();
                    System.err.println("MD5 verification failed for: " + remoteFilePath);
                }
            }

        } catch (IOException e) {
            System.err.println("Error in batch download: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
