#include <stdio.h>
#include <sqlite3.h>
#include <stdlib.h>

int main() {
    sqlite3 *db;
    char *err_msg = 0;

    // 1. 打开（如果不存在则创建）数据库文件
    int rc = sqlite3_open("db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "无法打开数据库: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    printf("数据库打开成功。\n");

    // 2. 创建用户表 (users)
    const char *sql_create_users = 
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT NOT NULL UNIQUE, "
        "password TEXT NOT NULL, "
        "is_admin INTEGER NOT NULL DEFAULT 0, "
        "is_member INTEGER NOT NULL DEFAULT 0, "
        "register_time DATETIME DEFAULT CURRENT_TIMESTAMP);";

    rc = sqlite3_exec(db, sql_create_users, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL错误 (users): %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }
    printf("用户表 'users' 创建成功。\n");

    // 3. 创建服务端文件信息表 (server_files)
    const char *sql_create_server_files =
        "CREATE TABLE IF NOT EXISTS server_files ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "filename TEXT NOT NULL, "
        "filesize INTEGER NOT NULL, "
        "md5 TEXT NOT NULL UNIQUE, "
        "upload_time DATETIME DEFAULT CURRENT_TIMESTAMP, "
        "download_count INTEGER DEFAULT 0);";
    
    rc = sqlite3_exec(db, sql_create_server_files, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL错误 (server_files): %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }
    printf("文件信息表 'server_files' 创建成功。\n");

    // 4. 添加默认管理员账户 (admin/admin)
    sqlite3_stmt *stmt;
    const char *sql_check_admin = "SELECT id FROM users WHERE username = 'admin';";
    rc = sqlite3_prepare_v2(db, sql_check_admin, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "预处理语句失败: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    if (sqlite3_step(stmt) != SQLITE_ROW) { // 管理员不存在
        const char *sql_insert_admin = 
            "INSERT INTO users (username, password, is_admin, is_member) "
            "VALUES ('admin', 'admin', 1, 1);";

        rc = sqlite3_exec(db, sql_insert_admin, 0, 0, &err_msg);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQL错误 (插入管理员): %s\n", err_msg);
            sqlite3_free(err_msg);
        } else {
            printf("默认管理员账户 'admin'/'admin' 创建成功。\n");
        }
    } else {
        printf("管理员账户已存在。\n");
    }
    sqlite3_finalize(stmt);


    // 5. 关闭数据库
    sqlite3_close(db);
    printf("数据库初始化完成。\n");

    return 0;
}
