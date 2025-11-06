import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class test {
    public static void main(String[] args) throws InterruptedException {
        // 启动服务端
        new Thread(() -> {
            EasyCloudDiskServer server = new EasyCloudDiskServer();
            server.start();
        }).start();
        Thread.sleep(1000);

        // 启动客户端
        EasyCloudDiskClient client = new EasyCloudDiskClient();
        client.start();

        // 1. 先列出cloud/download目录下的所有文件
        System.out.println("\n=== 列出云盘download目录下的文件 ===");
        client.listFiles("download");

        // 2. 批量下载cloud/download目录下的所有文件到本地downloads目录
        System.out.println("\n=== 开始从云盘download目录下载文件 ===");
        List<String> filesToDownload = new ArrayList<>();
        File downloadDir = new File("src/main/java/cloud/download");
        if (downloadDir.exists() && downloadDir.isDirectory()) {
            File[] files = downloadDir.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isFile()) {
                        filesToDownload.add("download/" + file.getName());
                    }
                }
            }
        }
        if (!filesToDownload.isEmpty()) {
            System.out.println("找到 " + filesToDownload.size() + " 个文件待下载");
            client.batchDownload(filesToDownload, "src/main/java/local/downloads");
            System.out.println("文件下载完成，保存在: src/main/java/local/downloads");
        } else {
            System.out.println("云盘download目录下没有找到文件");
        }

        // 3. 批量上传local/upload目录下的所有文件到cloud/upload
        System.out.println("\n=== 开始上传文件到云盘upload目录 ===");
        File uploadDir = new File("src/main/java/local/upload");
        if (uploadDir.exists() && uploadDir.isDirectory()) {
            List<String> filesToUpload = new ArrayList<>();
            File[] files = uploadDir.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isFile()) {
                        filesToUpload.add(file.getAbsolutePath());
                    }
                }
            }
            if (!filesToUpload.isEmpty()) {
                System.out.println("找到 " + filesToUpload.size() + " 个文件待上传");
                client.batchUpload(filesToUpload, "upload");
                System.out.println("文件上传完成，保存在云盘: upload");
            } else {
                System.out.println("本地upload目录下没有找到文件");
            }
        } else {
            System.out.println("本地upload目录不存在，请先创建目录: src/main/java/local/upload");
        }

        // 4. 验证上传结果
        System.out.println("\n=== 验证上传结果 ===");
        client.listFiles("upload");
        client.uploadDirectory(
            "src/main/java/local/upload",
            "upload");
    }
}
