import java.io.*;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class EasyCloudDiskClient {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 8888;

    /**
     * 启动客户端
     */
    public void start() {
        System.out.println("[Client] 启动客户端");
    }

    /**
     * 单线程上传文件
     *
     * @param localFilePath  本地文件路径
     * @param remoteFilePath 云盘文件路径
     */
    public void uploadFileSingleThread(String localFilePath, String remoteFilePath) {
        File file = new File(localFilePath);
        if (!file.exists()) {
            System.err.println("[客户端] 本地文件不存在: " + localFilePath);
            return;
        }
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
             FileInputStream fis = new FileInputStream(file)) {

            dos.writeUTF("UPLOAD");
            dos.writeUTF(remoteFilePath);
            dos.writeLong(file.length());

            byte[] buffer = new byte[4096];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                dos.write(buffer, 0, len);
            }
            dos.flush();

            String result = new DataInputStream(socket.getInputStream()).readUTF();
            System.out.println("[客户端] 上传结果: " + result);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 多线程上传文件（暂用单线程实现）
     *
     * @param localFilePath  本地文件路径
     * @param remoteFilePath 云盘文件路径
     */
    public void uploadFileMultiThread(String localFilePath, String remoteFilePath) {
        int threadCount = 5;
        File file = new File(localFilePath);
        if (!file.exists()) {
            System.err.println("[客户端] 本地文件不存在: " + localFilePath);
            return;
        }

        long fileSize = file.length();
        long blockSize = fileSize / threadCount;

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        try {
            for (int i = 0; i < threadCount; i++) {
                long startPos = i * blockSize;
                long endPos = (i == threadCount - 1) ? fileSize : (startPos + blockSize);
                executor.submit(() -> {
                    System.out.println("[客户端] 正在运行分片任务: " + startPos + "-" + endPos);
                    uploadBlock(file, remoteFilePath, startPos, endPos);
                    System.out.println("[客户端] 分片任务完成: " + startPos + "-" + endPos);
                });
            }
            executor.shutdown();
            if (!executor.awaitTermination(1, TimeUnit.MINUTES)) {
                System.err.println("[客户端] 多线程上传任务超时，部分任务可能未完成");
                executor.shutdownNow(); // 强制终止仍在运行的任务
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void uploadBlock(File file, String remoteFilePath, long startPos, long endPos) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
             RandomAccessFile raf = new RandomAccessFile(file, "r")) {

            dos.writeUTF("UPLOAD_BLOCK");
            dos.writeUTF(remoteFilePath);
            dos.writeLong(startPos);
            dos.writeLong(endPos);

            raf.seek(startPos);
            byte[] buffer = new byte[4096];
            long remaining = endPos - startPos;
            int len;

            while (remaining > 0 && (len = raf.read(buffer, 0, (int) Math.min(buffer.length, remaining))) != -1) {
                dos.write(buffer, 0, len);
                remaining -= len;
            }

            dos.flush();

            String result = new DataInputStream(socket.getInputStream()).readUTF();
            System.out.println("[客户端] 分片上传结果: " + result);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void mergeUploadedBlocks(String remoteFilePath) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {
            System.out.println("[客户端] 开始合并");
            dos.writeUTF("MERGE_BLOCKS");
            dos.writeUTF(remoteFilePath);

            String result = new DataInputStream(socket.getInputStream()).readUTF();
            System.out.println("[客户端] 合并结果: " + result);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 下载文件
     *
     * @param remoteFilePath 云盘文件路径
     * @param localFilePath  本地文件路径
     */
    public void downloadFile(String remoteFilePath, String localFilePath) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
             DataInputStream dis = new DataInputStream(socket.getInputStream())) {

            dos.writeUTF("DOWNLOAD");
            dos.writeUTF(remoteFilePath);

            long fileSize = dis.readLong();
            if (fileSize == -1) {
                System.err.println("[客户端] 云盘文件不存在: " + remoteFilePath);
                return;
            }

            writeToFile(dis, localFilePath, fileSize);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeToFile(DataInputStream dis, String localFilePath, long fileSize) throws IOException {
        File localFile = new File(localFilePath);
        if (!localFile.getParentFile().exists()) {
            localFile.getParentFile().mkdirs();
        }

        try (FileOutputStream fos = new FileOutputStream(localFile)) {
            byte[] buffer = new byte[4096*30];
            long remaining = fileSize;
            int len;
            while (remaining > 0 && (len = dis.read(buffer, 0, (int) Math.min(buffer.length, remaining))) != -1) {
                fos.write(buffer, 0, len);
                remaining -= len;
            }
        }
        System.out.println("[客户端] 下载完成: " + localFilePath);
    }

    /**
     * 多线程下载文件
     *
     * @param remoteFilePath 云盘文件路径
     * @param localFilePath  本地文件路径
     * @param threadCount    线程数量
     */
    public void downloadFileMultiThread(String remoteFilePath, String localFilePath, int threadCount) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
             DataInputStream dis = new DataInputStream(socket.getInputStream())) {

            dos.writeUTF("DOWNLOAD");
            dos.writeUTF(remoteFilePath);

            long fileSize = dis.readLong();
            if (fileSize == -1) {
                System.err.println("[客户端] 云盘文件不存在: " + remoteFilePath);
                return;
            }

            File localFile = new File(localFilePath);
            File parentDir = localFile.getParentFile();
            if (!parentDir.exists()) parentDir.mkdirs();

            long blockSize = fileSize / threadCount;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            File tempDir = createTempDirectory(parentDir);

            for (int i = 0; i < threadCount; i++) {
                long startPos = i * blockSize;
                long endPos = (i == threadCount - 1) ? fileSize - 1 : (i + 1) * blockSize - 1;
                String partPath = tempDir.getPath() + File.separator + "part_" + i;
                executor.submit(() -> downloadBlock(remoteFilePath, partPath, startPos, endPos));
            }

            executor.shutdown();
            while (!executor.isTerminated()) {
                // 等待所有线程完成
            }

            mergeBlocks(tempDir, localFilePath, threadCount);
            deleteDirectory(tempDir);
            System.out.println("[客户端] 多线程下载完成: " + localFilePath);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private File createTempDirectory(File parentDir) {
        File tempDir = new File(parentDir, ".temp_" + System.currentTimeMillis());
        tempDir.mkdirs();
        return tempDir;
    }

    private void downloadBlock(String remoteFilePath, String localFilePath, long startPos, long endPos) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
             DataInputStream dis = new DataInputStream(socket.getInputStream())) {

            dos.writeUTF("DOWNLOAD_BLOCK");
            dos.writeUTF(remoteFilePath);
            dos.writeLong(startPos);
            dos.writeLong(endPos);

            long blockSize = dis.readLong();
            if (blockSize == -1) {
                System.err.println("[客户端] 云盘文件块不存在: " + remoteFilePath);
                return;
            }

            writeToFile(dis, localFilePath, blockSize);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void mergeBlocks(File tempDir, String targetFilePath, int threadCount) {
        try (FileOutputStream fos = new FileOutputStream(targetFilePath)) {
            byte[] buffer = new byte[4096];
            for (int i = 0; i < threadCount; i++) {
                String partPath = tempDir.getPath() + File.separator + "part_" + i;
                File partFile = new File(partPath);
                if (partFile.exists()) {
                    try (FileInputStream fis = new FileInputStream(partFile)) {
                        int len;
                        while ((len = fis.read(buffer)) != -1) {
                            fos.write(buffer, 0, len);
                        }
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void deleteDirectory(File directory) {
        if (directory.isDirectory()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    deleteDirectory(file);
                }
            }
        }
        directory.delete();
    }

    /**
     * 列出远程目录内容
     *
     * @param
     */
    public void listFiles() {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
             DataInputStream dis = new DataInputStream(socket.getInputStream())) {

            System.out.println("[客户端] 云盘目录结构:");
            dos.writeUTF("LIST");
            dos.flush();
            System.out.println("[客户端] 已经发送UTF");
            String result = dis.readUTF();
            if (result=="SUCCESS"){
                System.out.println("打印完成");
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    /**
     * 批量上传多个文件
     *
     * @param localFiles  本地文件列表
     * @param remoteFiles 对应的云盘路径列表
     */
    public void batchUpload(List<String> localFiles, List<String> remoteFiles) {
        for (int i = 0; i < localFiles.size(); i++) {
            uploadFileSingleThread(localFiles.get(i), remoteFiles.get(i));
        }
    }

    /**
     * 批量下载多个文件（单线程）
     *
     * @param remoteFiles 云盘文件列表
     * @param localFiles  本地保存路径列表
     */
    public void batchDownload(List<String> remoteFiles, List<String> localFiles) {
        for (int i = 0; i < remoteFiles.size(); i++) {
            downloadFile(remoteFiles.get(i), localFiles.get(i));
        }
    }

    /**
     * 批量下载多个文件（多线程）
     *
     * @param remoteFiles 云盘文件列表
     * @param localFiles  本地保存路径列表
     * @param threadCount 线程数
     */
    public void batchDownload(List<String> remoteFiles, List<String> localFiles, int threadCount) {
        for (int i = 0; i < remoteFiles.size(); i++) {
            downloadFileMultiThread(remoteFiles.get(i), localFiles.get(i), threadCount);
        }
    }
}
