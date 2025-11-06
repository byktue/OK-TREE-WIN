import util.FileGenerator;
import util.MD5Util;

public class Main {
    public static void main(String[] args) throws Exception {
        // 测试变量定义
        long start, end;
        double task1, task2, task3;

        // 启动服务端
        new Thread(() -> {
            EasyCloudDiskServer server = new EasyCloudDiskServer();
            server.start();
        }).start();
        Thread.sleep(1000);


        // 启动客户端
        EasyCloudDiskClient client = new EasyCloudDiskClient();
        client.start();

        // 生成必要的测试文件
        FileGenerator.generateFile();

        // 单线程上传 10MB 文件的耗时
        start = System.nanoTime();

        client.uploadFileSingleThread("src/main/java/local/file10MB", "a.txt");

        end = System.nanoTime();
        task1 = (end - start) / 1_000_000_000.0;
        Thread.sleep(500);

        // 多线程上传 10MB 文件的耗时
        start = System.nanoTime();

        client.uploadFileMultiThread("src/main/java/local/file10MB", "b.txt");

        end = System.nanoTime();
        task2 = (end - start) / 1_000_000_000.0;
        Thread.sleep(1000);

        // 循环 10 次单线程下载 1MB 文件的耗时
        start = System.nanoTime();

        for (int i = 0; i < 10; i++) {
            client.downloadFile("file1MB", "src/main/java/local/chunk-" + i + ".txt");
        }

        end = System.nanoTime();
        task3 = (end - start) / 1_000_000_000.0;
        Thread.sleep(500);


        if (MD5Util.isSameFile("src/main/java/local/file10MB", "src/main/java/cloud/a.txt")) {
            System.out.println("[功能测试] 单线程上传文件功能通过");
        } else {
            System.out.println("[功能测试] 单线程上传文件功能未通过");
        }

        if (MD5Util.isSameFile("src/main/java/local/file10MB", "src/main/java/cloud/b.txt")) {
            System.out.println("[功能测试] 多线程上传文件功能通过");
        } else {
            System.out.println("[功能测试] 多线程上传文件功能未通过");
        }

        boolean flag = true;
        for (int i = 0; i < 10; i++) {
            if (!MD5Util.isSameFile("src/main/java/cloud/file1MB", "src/main/java/local/chunk-" + i + ".txt")) {
                flag = false;
            }
        }
        if (flag) {
            System.out.println("[功能测试] 单线程下载文件功能通过");
        } else {
            System.out.println("[功能测试] 单线程下载文件功能未通过");
        }

        System.out.printf("[性能测试] 单线程上传 10MB 文件的耗时 耗时: %.3f s%n", task1);
        System.out.printf("[性能测试] 多线程上传 10MB 文件的耗时 耗时: %.3f s%n", task2);
        System.out.printf("[性能测试] 循环 10 次单线程下载 1MB 文件的耗时 耗时: %.3f s%n", task3);
    }
}