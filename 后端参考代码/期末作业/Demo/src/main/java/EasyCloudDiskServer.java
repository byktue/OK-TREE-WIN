import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class EasyCloudDiskServer {
    private static final int PORT = 8888;
    private static final String CLOUD_STORAGE_DIR = "src/main/java/cloud/";
    private void handleList() throws IOException {
        System.out.println("[服务端] 返回云盘结构中");
        File file = new File("src/main/java/cloud/");
        if (file.exists() && file.isDirectory()) {
            listFilesRecursive(file, 0); // 从缩进0层开始
        } else {
            System.out.println("指定的路径不存在或不是一个有效目录");
        }
    }
    /**
     * 服务端启动
     */
    public void start() {
        // TODO
        // 初始化服务器
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("服务器启动，监听端口：" + PORT);
            ExecutorService executor = Executors.newCachedThreadPool();
            handleList();
            while (true) {
                Socket clientSocket = serverSocket.accept();
                executor.submit(() -> handleClient(clientSocket));
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void handleClient(Socket socket) {
        try (
                DataInputStream dis = new DataInputStream(socket.getInputStream());
                DataOutputStream dos = new DataOutputStream(socket.getOutputStream())
        ) {
            String command = dis.readUTF();
            String remotePath = dis.readUTF();
            File file = new File(CLOUD_STORAGE_DIR + remotePath);

            switch (command) {
                // 处理不同请求
                case "UPLOAD" -> handleUpload(dis, dos, file);
                case "UPLOAD_BLOCK" -> {
                    long startPos = dis.readLong();
                    long endPos = dis.readLong(); // 修正为读取
                    File fileBlock = new File(CLOUD_STORAGE_DIR + remotePath);
                    handleUploadBlock(dis, dos, fileBlock, startPos, endPos);
                }
                case "DOWNLOAD" -> handleDownload(dos, file, -1, -1);
                case "DOWNLOAD_BLOCK" -> {
                    long startPos = dis.readLong();
                    long endPos = dis.readLong();
                    handleDownload(dos, file, startPos, endPos);
                }
                case "LIST" -> handleList();
            }
        } catch (IOException e) {
            if (!isConnectionReset(e)) {
                e.printStackTrace();
            }
        }
    }

    private void handleUpload(DataInputStream dis, DataOutputStream dos, File file) throws IOException {
        long fileSize = dis.readLong();
        file.getParentFile().mkdirs(); // 确保目录存在
        try (FileOutputStream fos = new FileOutputStream(file)) {
            byte[] buffer = new byte[4096];
            long received = 0;
            while (received < fileSize) {
                int len = dis.read(buffer, 0, (int) Math.min(buffer.length, fileSize - received));
                fos.write(buffer, 0, len);
                received += len;
            }
        }
        dos.writeUTF("SUCCESS");
    }

    private void handleUploadBlock(DataInputStream dis, OutputStream out, File file, long startPos, long endPos) {
        try {
            // 确保文件所在目录存在
            file.getParentFile().mkdirs();

            // 使用 RandomAccessFile 以支持从指定位置写入
            try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
                raf.seek(startPos); // 定位到指定偏移量

                byte[] buffer = new byte[4096];
                long remaining = endPos - startPos; // 计算剩余字节数
                int len;

                while (remaining > 0 && (len = dis.read(buffer, 0, (int) Math.min(buffer.length, remaining))) != -1) {
                    raf.write(buffer, 0, len);
                    remaining -= len;
                }
                if (remaining == 0) {
                    System.out.println("[服务端] 当前block已上传成功");
                }
            }

            // 向客户端发送上传成功响应
            try (DataOutputStream dos = new DataOutputStream(out)) {
                dos.writeUTF("SUCCESS");
            }

            System.out.printf("[Server] 文件块上传完成: %s 起始位置: %d, 结束位置: %d%n",
                    file.getName(), startPos, endPos);

        } catch (IOException e) {
            e.printStackTrace();
            try (DataOutputStream dos = new DataOutputStream(out)) {
                dos.writeUTF("FAIL");
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    /**
     * 合并所有分块文件为一个完整的文件
     *
     * @param targetFile 最终目标文件
     * @return 是否合并成功
     */
    private boolean mergeBlockFiles(File targetFile) {
        File blockDir = new File(targetFile.getParent(), ".block_" + targetFile.getName());
        if (!blockDir.exists()) {
            System.err.println("[Server] 分块目录不存在: " + blockDir.getAbsolutePath());
            return false;
        }

        File[] partFiles = blockDir.listFiles((dir, name) -> name.startsWith("part_"));
        if (partFiles == null || partFiles.length == 0) {
            System.err.println("[Server] 没有找到任何分块文件");
            return false;
        }

        // 对分块文件排序（part_0, part_1, ...）
        Arrays.sort(partFiles);

        try (FileOutputStream fos = new FileOutputStream(targetFile)) {
            byte[] buffer = new byte[4096];
            for (File partFile : partFiles) {
                try (FileInputStream fis = new FileInputStream(partFile)) {
                    int len;
                    while ((len = fis.read(buffer)) != -1) {
                        fos.write(buffer, 0, len);
                    }
                }
            }
            System.out.println("[Server] 文件合并完成: " + targetFile.getName());

            // 可选：删除临时分块文件夹
            deleteDirectory(blockDir);

            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
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
        if (!directory.delete()) {
            System.err.println("无法删除目录或文件: " + directory.getAbsolutePath());
        }
    }

    private void handleDownload(DataOutputStream dos, File file, long startPos, long endPos) throws IOException {
        if (!file.exists()) {
            dos.writeLong(-1);
            return;
        }

        long fileSize = file.length();
        long actualStart = startPos >= 0 ? startPos : 0;
        long actualEnd = endPos >= 0 ? endPos : fileSize - 1;

        long blockSize = actualEnd - actualStart + 1;
        dos.writeLong(blockSize);

        try (FileInputStream fis = new FileInputStream(file)) {
            fis.skip(actualStart);
            byte[] buffer = new byte[4096];
            long bytesRead = 0;
            while (bytesRead < blockSize) {
                int len = fis.read(buffer);
                if (len == -1) break;
                int writeLength = (int) Math.min(len, blockSize - bytesRead);
                dos.write(buffer, 0, writeLength);
                bytesRead += writeLength;
            }
        }
    }

    private void listFilesRecursive(File file, int depth) {
        // 添加缩进效果
        StringBuilder indent = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            indent.append("  "); // 两个空格表示一层缩进
        }

        // 打印当前文件/目录名称
        System.out.println(indent + "|-- " + file.getName());

        // 如果是目录，则递归处理其子文件
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    listFilesRecursive(child, depth + 1); // 子级增加缩进
                }
            }
        }
    }

    private boolean isConnectionReset(IOException e) {
        String msg = e.getMessage();
        return msg != null && (msg.contains("Connection reset by peer") || msg.contains("Broken pipe"));
    }
}

