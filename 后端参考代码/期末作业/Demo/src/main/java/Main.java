import util.FileGenerator;
import util.MD5Util;

public class Main {
    public static void main(String[] args) throws Exception {
        // 测试变量定义
        long start, end;
        double task1, task2, task3, task4;

        // 启动服务端
        new Thread(() -> {
            EasyCloudDiskServer server = new EasyCloudDiskServer();
            server.start();
        }).start();
        Thread.sleep(1000);
        System.out.println("服务器启动成功");

        // 启动客户端
        EasyCloudDiskClient client = new EasyCloudDiskClient();
        client.start();
        System.out.println("客户端启动成功");

        // 生成必要的测试文件
        FileGenerator.generateFile();
        System.out.println("测试文件生成完毕");

        System.out.println("查看云盘结构");

        // 单线程上传 10MB 文件的耗时
        System.out.println("单线程上传文件中");
        start = System.nanoTime();

        client.uploadFileSingleThread("src/main/java/local/file10MB", "a.txt");

        end = System.nanoTime();
        task1 = (end - start) / 1_000_000_000.0;
        Thread.sleep(500);
        System.out.println("单线程上传文件完毕");

        // 多线程上传 10MB 文件的耗时
        System.out.println("多线程上传文件中");
        start = System.nanoTime();

        client.uploadFileMultiThread("src/main/java/local/file10MB", "b.txt");

        end = System.nanoTime();
        task2 = (end - start) / 1_000_000_000.0;
        Thread.sleep(1000);
        System.out.println("多线程上传文件完毕");

        // 循环 10 次单线程下载 1MB 文件的耗时
        System.out.println("单线程下载文件中");
        start = System.nanoTime();

        for (int i = 0; i < 10; i++) {
            client.downloadFile("file1MB", "src/main/java/local/chunk-" + i + ".txt");
        }

        end = System.nanoTime();
        task3 = (end - start) / 1_000_000_000.0;
        Thread.sleep(500);
        System.out.println("单线程下载文件完毕");

        System.out.println("多线程下载文件中");
        start = System.nanoTime();

        client.downloadFileMultiThread("a.txt", "src/main/java/local/" + "a.txt", 5);

        end = System.nanoTime();

        task4 = (end - start) / 1_000_000_000.0;
        Thread.sleep(500);
        System.out.println("多线程下载文件完毕");

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
        System.out.printf("[性能测试] 多线程下载 10MB 文件的耗时 耗时: %.3f s%n", task4);
    }
}