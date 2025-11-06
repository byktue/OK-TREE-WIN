#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sqlite3.h>
#include <json-c/json.h>
#include <openssl/md5.h>
#include <sys/stat.h>
#include <dirent.h>

#define BUFFER_SIZE 4096
#define PORT 8888
#define MAX_CLIENTS 30
#define STORAGE_DIR "server_storage"
#define MEMBER_LIMIT 20480 // 20KB

// 全局变量
sqlite3 *db;
pthread_mutex_t db_mutex;
pthread_mutex_t clients_mutex;

// 客户端信息结构
typedef struct {
    int sock;
    struct sockaddr_in address;
    int user_id;
    char username[50];
    int is_logged_in;
    int is_admin;
    int is_member;
} client_t;

client_t *clients[MAX_CLIENTS];

// 函数声明
void add_client(client_t *cl);
void remove_client(int sock);
void print_connected_clients();
char* calculate_file_md5(const char *filepath);
void handle_client(void *arg);
json_object* process_request(json_object *req, client_t *client_info);

// 主函数
int main() {
    mkdir(STORAGE_DIR, 0777);

    if (sqlite3_open("db", &db)) {
        fprintf(stderr, "无法打开数据库: %s\n", sqlite3_errmsg(db));
        return 1;
    } else {
        fprintf(stdout, "数据库打开成功\n");
    }

    pthread_mutex_init(&db_mutex, NULL);
    pthread_mutex_init(&clients_mutex, NULL);

    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    pthread_t tid;

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == -1) {
        perror("无法创建套接字");
        return 1;
    }

    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(SO_REUSEADDR) 失败");
        exit(EXIT_FAILURE);
    }
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("绑定失败");
        close(server_sock);
        return 1;
    }
    printf("服务器绑定成功\n");

    listen(server_sock, 5);
    printf("服务器正在监听端口 %d...\n", PORT);
    printf("等待客户端连接...\n");

    while (1) {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_sock < 0) {
            perror("接受连接失败");
            continue;
        }

        printf("接受来自 %s:%d 的连接\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        client_t *cli = (client_t *)malloc(sizeof(client_t));
        cli->address = client_addr;
        cli->sock = client_sock;
        cli->user_id = -1;
        cli->is_logged_in = 0;
        cli->is_admin = 0;
        cli->is_member = 0;
        memset(cli->username, 0, sizeof(cli->username));

        add_client(cli);

        if (pthread_create(&tid, NULL, (void *)handle_client, (void *)cli) < 0) {
            perror("无法创建线程");
            free(cli);
            close(client_sock);
        }
    }

    close(server_sock);
    sqlite3_close(db);
    pthread_mutex_destroy(&db_mutex);
    pthread_mutex_destroy(&clients_mutex);
    return 0;
}

void add_client(client_t *cl) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i]) {
            clients[i] = cl;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

void remove_client(int sock) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->sock == sock) {
            printf("客户端断开连接: %s (套接字: %d)\n", clients[i]->is_logged_in ? clients[i]->username : "未登录", sock);
            free(clients[i]);
            clients[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    print_connected_clients();
}

void print_connected_clients() {
    pthread_mutex_lock(&clients_mutex);
    printf("\n--- 当前在线客户端 ---\n");
    int count = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->is_logged_in) {
            const char* role = clients[i]->is_admin ? "管理员" : (clients[i]->is_member ? "会员" : "普通用户");
            printf("  - %s (用户ID: %d, 身份: %s)\n", clients[i]->username, clients[i]->user_id, role);
            count++;
        }
    }
    if (count == 0) {
        printf("  无已登录的客户端。\n");
    }
    printf("----------------------\n");
    pthread_mutex_unlock(&clients_mutex);
}

char* calculate_file_md5(const char *filepath) {
    unsigned char c[MD5_DIGEST_LENGTH];
    FILE *inFile = fopen(filepath, "rb");
    MD5_CTX mdContext;
    int bytes;
    unsigned char data[1024];
    
    char *md5_str = (char*)malloc(MD5_DIGEST_LENGTH * 2 + 1);
    if (md5_str == NULL) {
        fprintf(stderr, "为MD5字符串分配内存失败\n");
        if (inFile) fclose(inFile);
        return NULL;
    }

    if (inFile == NULL) {
        fprintf(stderr, "文件 %s 无法打开。\n", filepath);
        free(md5_str);
        return NULL;
    }

    MD5_Init(&mdContext);
    while ((bytes = fread(data, 1, 1024, inFile)) != 0) {
        MD5_Update(&mdContext, data, bytes);
    }
    MD5_Final(c, &mdContext);
    
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(&md5_str[i * 2], "%02x", (unsigned int)c[i]);
    }
    md5_str[MD5_DIGEST_LENGTH * 2] = '\0';

    fclose(inFile);
    return md5_str;
}

void send_response(int sock, json_object *response) {
    const char *response_str = json_object_to_json_string(response);
    uint32_t len = htonl(strlen(response_str));
    write(sock, &len, sizeof(len));
    write(sock, response_str, strlen(response_str));
}

int read_all(int sock, void *buf, size_t len) {
    size_t bytes_read = 0;
    while (bytes_read < len) {
        ssize_t res = read(sock, (char*)buf + bytes_read, len - bytes_read);
        if (res <= 0) return -1;
        bytes_read += res;
    }
    return 0;
}

int receive_file(int sock, const char *filepath, long long filesize) {
    FILE *fp = fopen(filepath, "wb");
    if (!fp) {
        perror("打开文件写入失败");
        return -1;
    }
    char buffer[BUFFER_SIZE];
    long long received_size = 0;
    while (received_size < filesize) {
        int bytes_to_read = (filesize - received_size < BUFFER_SIZE) ? (filesize - received_size) : BUFFER_SIZE;
        int bytes_read = read(sock, buffer, bytes_to_read);
        if (bytes_read <= 0) {
            fclose(fp);
            return -1;
        }
        fwrite(buffer, 1, bytes_read, fp);
        received_size += bytes_read;
    }
    fclose(fp);
    return 0;
}

int send_file(int sock, const char *filepath) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return -1;
    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
        if (write(sock, buffer, bytes_read) < 0) {
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    return 0;
}

static int single_value_callback(void *data, int argc, char **argv, char **azColName) {
    if (argc > 0 && argv[0]) strcpy((char *)data, argv[0]);
    return 0;
}

void record_user_upload(int user_id, const char* filename, long long filesize) {
    char user_upload_table[100];
    sprintf(user_upload_table, "user_uploads_%d", user_id);
    char create_table_sql[256];
    sprintf(create_table_sql, 
            "CREATE TABLE IF NOT EXISTS %s ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "filename TEXT, filesize INTEGER, "
            "upload_time DATETIME DEFAULT CURRENT_TIMESTAMP);", 
            user_upload_table);
    char insert_sql[1024];
    sprintf(insert_sql, "INSERT INTO %s (filename, filesize) VALUES ('%s', %lld);", 
            user_upload_table, filename, filesize);
    sqlite3_exec(db, create_table_sql, 0, 0, NULL);
    sqlite3_exec(db, insert_sql, 0, 0, NULL);
}

void do_register(json_object *req, json_object *resp) {
    const char *username = json_object_get_string(json_object_object_get(req, "username"));
    const char *password = json_object_get_string(json_object_object_get(req, "password"));
    char sql[256], *err_msg = 0;
    sprintf(sql, "INSERT INTO users (username, password) VALUES ('%s', '%s');", username, password);
    pthread_mutex_lock(&db_mutex);
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    pthread_mutex_unlock(&db_mutex);
    if (rc != SQLITE_OK) {
        json_object_object_add(resp, "status", json_object_new_string("ERROR"));
        json_object_object_add(resp, "message", json_object_new_string("用户名已存在或数据库错误。"));
        sqlite3_free(err_msg);
    } else {
        json_object_object_add(resp, "status", json_object_new_string("SUCCESS"));
        json_object_object_add(resp, "message", json_object_new_string("注册成功。"));
    }
}

void do_login(json_object *req, json_object *resp, client_t *client_info) {
    const char *username = json_object_get_string(json_object_object_get(req, "username"));
    const char *password = json_object_get_string(json_object_object_get(req, "password"));
    char sql[512];
    sqlite3_stmt *stmt;
    sprintf(sql, "SELECT id, is_admin, is_member FROM users WHERE username = ? AND password = ?;");
    pthread_mutex_lock(&db_mutex);
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            client_info->user_id = sqlite3_column_int(stmt, 0);
            strcpy(client_info->username, username);
            client_info->is_logged_in = 1;
            client_info->is_admin = sqlite3_column_int(stmt, 1);
            client_info->is_member = sqlite3_column_int(stmt, 2);
            json_object_object_add(resp, "status", json_object_new_string("SUCCESS"));
            json_object_object_add(resp, "message", json_object_new_string("登录成功。"));
            json_object_object_add(resp, "user_id", json_object_new_int(client_info->user_id));
            json_object_object_add(resp, "username", json_object_new_string(client_info->username));
            json_object_object_add(resp, "is_admin", json_object_new_int(client_info->is_admin));
            json_object_object_add(resp, "is_member", json_object_new_int(client_info->is_member));
            print_connected_clients();
        } else {
            json_object_object_add(resp, "status", json_object_new_string("ERROR"));
            json_object_object_add(resp, "message", json_object_new_string("用户名不存在或密码错误。"));
        }
    } else {
         json_object_object_add(resp, "status", json_object_new_string("ERROR"));
         json_object_object_add(resp, "message", json_object_new_string("数据库查询失败。"));
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_mutex);
}

void do_upload(json_object *req, json_object *resp, client_t *client_info) {
    const char *filename = json_object_get_string(json_object_object_get(req, "filename"));
    long long filesize = json_object_get_int64(json_object_object_get(req, "filesize"));
    const char *md5_from_client = json_object_get_string(json_object_object_get(req, "md5"));
    
    if (!client_info->is_member && filesize > MEMBER_LIMIT) {
        json_object_object_add(resp, "status", json_object_new_string("ERROR"));
        json_object_object_add(resp, "message", json_object_new_string("权限不足：普通用户上传文件大小不能超过20KB。"));
        return;
    }

    char sql[512];
    sqlite3_stmt *stmt;
    sprintf(sql, "SELECT filename FROM server_files WHERE md5 = ?;");
    
    pthread_mutex_lock(&db_mutex);
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, md5_from_client, -1, SQLITE_STATIC);
    
    if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        sqlite3_finalize(stmt);
        record_user_upload(client_info->user_id, filename, filesize);
        pthread_mutex_unlock(&db_mutex);
        
        json_object_object_add(resp, "status", json_object_new_string("SUCCESS_SECONDUPLOAD"));
        json_object_object_add(resp, "message", json_object_new_string("文件已存在于服务器，秒传成功。"));
        return;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_mutex);

    json_object_object_add(resp, "status", json_object_new_string("PROCEED_UPLOAD"));
    json_object_object_add(resp, "message", json_object_new_string("服务器准备就绪，请开始上传文件。"));
}

void do_download(json_object *req, json_object *resp, client_t *client_info) {
    const char* filename = json_object_get_string(json_object_object_get(req, "filename"));
    char filepath[512];
    sprintf(filepath, "%s/%s", STORAGE_DIR, filename);
    struct stat file_stat;
    if (stat(filepath, &file_stat) < 0) {
        json_object_object_add(resp, "status", json_object_new_string("ERROR"));
        json_object_object_add(resp, "message", json_object_new_string("文件在服务器上不存在。"));
        return;
    }
    long long filesize = file_stat.st_size;
    if (!client_info->is_member && filesize > MEMBER_LIMIT) {
        json_object_object_add(resp, "status", json_object_new_string("ERROR"));
        json_object_object_add(resp, "message", json_object_new_string("权限不足：普通用户下载文件大小不能超过20KB。"));
        return;
    }
    json_object_object_add(resp, "status", json_object_new_string("PROCEED_DOWNLOAD"));
    json_object_object_add(resp, "message", json_object_new_string("文件找到，开始下载。"));
    json_object_object_add(resp, "filesize", json_object_new_int64(filesize));
}

struct query_result { json_object *jarray; };
static int query_to_json_callback(void *data, int argc, char **argv, char **azColName) {
    struct query_result *res = (struct query_result *)data;
    json_object *jrow = json_object_new_object();
    for (int i = 0; i < argc; i++) {
        json_object_object_add(jrow, azColName[i], json_object_new_string(argv[i] ? argv[i] : "NULL"));
    }
    json_object_array_add(res->jarray, jrow);
    return 0;
}

void do_search(json_object *req, json_object *resp) {
    const char* keyword = json_object_get_string(json_object_object_get(req, "keyword"));
    char sql[512];
    sprintf(sql, "SELECT filename, filesize, download_count FROM server_files WHERE filename LIKE '%%%s%%';", keyword);
    struct query_result res;
    res.jarray = json_object_new_array();
    pthread_mutex_lock(&db_mutex);
    sqlite3_exec(db, sql, query_to_json_callback, &res, NULL);
    pthread_mutex_unlock(&db_mutex);
    json_object_object_add(resp, "status", json_object_new_string("SUCCESS"));
    json_object_object_add(resp, "data", res.jarray);
}

void do_view_history(json_object *req, json_object *resp, client_t *client_info) {
    const char *type = json_object_get_string(json_object_object_get(req, "type"));
    char table_name[100];
    sprintf(table_name, "user_%ss_%d", type, client_info->user_id);
    char sql[512];
    sprintf(sql, "SELECT id, filename, filesize, %s_time FROM %s;", type, table_name);
    struct query_result res = { .jarray = json_object_new_array() };
    pthread_mutex_lock(&db_mutex);
    char check_sql[256];
    sqlite3_stmt *stmt;
    sprintf(check_sql, "SELECT name FROM sqlite_master WHERE type='table' AND name='%s';", table_name);
    if (sqlite3_prepare_v2(db, check_sql, -1, &stmt, 0) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            sqlite3_exec(db, sql, query_to_json_callback, &res, NULL);
        }
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&db_mutex);
    json_object_object_add(resp, "status", json_object_new_string("SUCCESS"));
    json_object_object_add(resp, "data", res.jarray);
}

// **重大修改**: do_delete_history
void do_delete_history(json_object *req, json_object *resp, client_t *client_info) {
    const char *type = json_object_get_string(json_object_object_get(req, "type"));
    int record_id = json_object_get_int(json_object_object_get(req, "record_id"));
    
    char table_name[100];
    sprintf(table_name, "user_%ss_%d", type, client_info->user_id);
    char sql[256];

    pthread_mutex_lock(&db_mutex);
    if (record_id != -1 && strcmp(type, "download") == 0) {
        // 如果是删除单条下载记录，先查询出文件名
        char filename_buf[256] = {0};
        sprintf(sql, "SELECT filename FROM %s WHERE id = %d;", table_name, record_id);
        sqlite3_exec(db, sql, single_value_callback, filename_buf, NULL);

        if (strlen(filename_buf) > 0) {
            json_object_object_add(resp, "deleted_filename", json_object_new_string(filename_buf));
        }
    }

    if (record_id == -1) { // 删除全部
        sprintf(sql, "DELETE FROM %s;", table_name);
    } else { // 删除单条
        sprintf(sql, "DELETE FROM %s WHERE id = %d;", table_name, record_id);
    }

    sqlite3_exec(db, sql, 0, 0, NULL);
    pthread_mutex_unlock(&db_mutex);

    json_object_object_add(resp, "status", json_object_new_string("SUCCESS"));
    json_object_object_add(resp, "message", json_object_new_string("历史记录已删除。"));
}

void do_delete_account(json_object *resp, client_t *client_info) {
    char sql[512], table_name[100];
    pthread_mutex_lock(&db_mutex);
    sprintf(sql, "DELETE FROM users WHERE id = %d;", client_info->user_id);
    sqlite3_exec(db, sql, 0, 0, NULL);
    sprintf(table_name, "user_uploads_%d", client_info->user_id);
    sprintf(sql, "DROP TABLE IF EXISTS %s;", table_name);
    sqlite3_exec(db, sql, 0, 0, NULL);
    sprintf(table_name, "user_downloads_%d", client_info->user_id);
    sprintf(sql, "DROP TABLE IF EXISTS %s;", table_name);
    sqlite3_exec(db, sql, 0, 0, NULL);
    pthread_mutex_unlock(&db_mutex);
    json_object_object_add(resp, "status", json_object_new_string("SUCCESS"));
    json_object_object_add(resp, "message", json_object_new_string("您的账户已成功删除。"));
}

void do_admin_set_member(json_object *req, json_object *resp) {
    const char *target_user = json_object_get_string(json_object_object_get(req, "target_user"));
    int is_member = json_object_get_int(json_object_object_get(req, "is_member"));
    char sql[256];
    sprintf(sql, "UPDATE users SET is_member = %d WHERE username = '%s';", is_member, target_user);
    pthread_mutex_lock(&db_mutex);
    sqlite3_exec(db, sql, 0, 0, NULL);
    int changes = sqlite3_changes(db);
    pthread_mutex_unlock(&db_mutex);
    if (changes > 0) {
        json_object_object_add(resp, "status", json_object_new_string("SUCCESS"));
        char msg[128];
        sprintf(msg, "用户 '%s' 的会员状态已更新。", target_user);
        json_object_object_add(resp, "message", json_object_new_string(msg));
    } else {
        json_object_object_add(resp, "status", json_object_new_string("ERROR"));
        json_object_object_add(resp, "message", json_object_new_string("未找到该用户。"));
    }
}

void do_admin_delete_user(json_object *req, json_object *resp) {
    const char *target_user = json_object_get_string(json_object_object_get(req, "target_user"));
    if (strcmp(target_user, "admin") == 0) {
        json_object_object_add(resp, "status", json_object_new_string("ERROR"));
        json_object_object_add(resp, "message", json_object_new_string("不能删除管理员账户。"));
        return;
    }
    char sql[512], target_id_str[20] = {0};
    pthread_mutex_lock(&db_mutex);
    sprintf(sql, "SELECT id FROM users WHERE username = '%s';", target_user);
    sqlite3_exec(db, sql, single_value_callback, target_id_str, NULL);
    if (strlen(target_id_str) == 0) {
        pthread_mutex_unlock(&db_mutex);
        json_object_object_add(resp, "status", json_object_new_string("ERROR"));
        json_object_object_add(resp, "message", json_object_new_string("未找到该用户。"));
        return;
    }
    int target_id = atoi(target_id_str);
    sprintf(sql, "DELETE FROM users WHERE id = %d;", target_id);
    sqlite3_exec(db, sql, 0, 0, NULL);
    char table_name[100];
    sprintf(table_name, "user_uploads_%d", target_id);
    sprintf(sql, "DROP TABLE IF EXISTS %s;", table_name);
    sqlite3_exec(db, sql, 0, 0, NULL);
    sprintf(table_name, "user_downloads_%d", target_id);
    sprintf(sql, "DROP TABLE IF EXISTS %s;", table_name);
    sqlite3_exec(db, sql, 0, 0, NULL);
    pthread_mutex_unlock(&db_mutex);
    json_object_object_add(resp, "status", json_object_new_string("SUCCESS"));
    char msg[128];
    sprintf(msg, "用户 '%s' 及其所有关联数据已被删除。", target_user);
    json_object_object_add(resp, "message", json_object_new_string(msg));
}

json_object* process_request(json_object *req, client_t *client_info) {
    json_object *resp = json_object_new_object();
    const char *command = json_object_get_string(json_object_object_get(req, "command"));

    if (strcmp(command, "REGISTER") == 0)      { do_register(req, resp); } 
    else if (strcmp(command, "LOGIN") == 0)    { do_login(req, resp, client_info); } 
    else if (client_info->is_logged_in) {
        if (strcmp(command, "UPLOAD") == 0)             { do_upload(req, resp, client_info); } 
        else if (strcmp(command, "DOWNLOAD") == 0)          { do_download(req, resp, client_info); } 
        else if (strcmp(command, "SEARCH") == 0)            { do_search(req, resp); } 
        else if (strcmp(command, "VIEW_HISTORY") == 0)      { do_view_history(req, resp, client_info); } 
        else if (strcmp(command, "DELETE_HISTORY") == 0)    { do_delete_history(req, resp, client_info); } 
        else if (strcmp(command, "DELETE_ACCOUNT") == 0)    { do_delete_account(resp, client_info); } 
        else if (client_info->is_admin) {
            if (strcmp(command, "ADMIN_SET_MEMBER") == 0)   { do_admin_set_member(req, resp); } 
            else if (strcmp(command, "ADMIN_DELETE_USER") == 0) { do_admin_delete_user(req, resp); }
            else {
                json_object_object_add(resp, "status", json_object_new_string("ERROR"));
                json_object_object_add(resp, "message", json_object_new_string("未知管理员命令。"));
            }
        } else {
            json_object_object_add(resp, "status", json_object_new_string("ERROR"));
            json_object_object_add(resp, "message", json_object_new_string("未知命令或权限不足。"));
        }
    } else {
        json_object_object_add(resp, "status", json_object_new_string("ERROR"));
        json_object_object_add(resp, "message", json_object_new_string("需要认证，请先登录。"));
    }
    return resp;
}

void handle_client(void *arg) {
    client_t *cli = (client_t *)arg;
    char buffer[BUFFER_SIZE];
    while (1) {
        uint32_t len;
        if (read_all(cli->sock, &len, sizeof(len)) != 0) break;
        len = ntohl(len);
        if (len >= BUFFER_SIZE) {
            fprintf(stderr, "来自套接字 %d 的请求过大，断开连接。\n", cli->sock);
            break;
        }
        if (read_all(cli->sock, buffer, len) != 0) break;
        buffer[len] = '\0';
        json_object *req = json_tokener_parse(buffer);
        if (!req) {
            fprintf(stderr, "来自套接字 %d 的JSON无效，断开连接。\n", cli->sock);
            break;
        }
        
        json_object *resp = process_request(req, cli);
        const char *cmd = json_object_get_string(json_object_object_get(req, "command"));
        const char *status_str = json_object_get_string(json_object_object_get(resp, "status"));

        send_response(cli->sock, resp);

        if (status_str && strcmp(status_str, "PROCEED_UPLOAD") == 0) {
            const char *filename = json_object_get_string(json_object_object_get(req, "filename"));
            long long filesize = json_object_get_int64(json_object_object_get(req, "filesize"));
            const char *md5_from_client = json_object_get_string(json_object_object_get(req, "md5"));

            char temp_filepath[512];
            sprintf(temp_filepath, "%s/%s.tmp", STORAGE_DIR, filename);
            if (receive_file(cli->sock, temp_filepath, filesize) != 0) {
                fprintf(stderr, "接收文件 %s 失败\n", filename);
                remove(temp_filepath);
            } else {
                char *received_md5 = calculate_file_md5(temp_filepath);
                json_object *final_resp = json_object_new_object();
                if (received_md5 && strcmp(received_md5, md5_from_client) == 0) {
                    char final_filepath[512];
                    sprintf(final_filepath, "%s/%s", STORAGE_DIR, filename);
                    rename(temp_filepath, final_filepath);
                    pthread_mutex_lock(&db_mutex);
                    char sql[512];
                    sprintf(sql, "INSERT OR IGNORE INTO server_files (filename, filesize, md5) VALUES ('%s', %lld, '%s');", filename, filesize, received_md5);
                    sqlite3_exec(db, sql, 0, 0, NULL);
                    record_user_upload(cli->user_id, filename, filesize);
                    pthread_mutex_unlock(&db_mutex);
                    json_object_object_add(final_resp, "status", json_object_new_string("SUCCESS"));
                    json_object_object_add(final_resp, "message", json_object_new_string("文件上传并校验成功。"));
                } else {
                    remove(temp_filepath);
                    json_object_object_add(final_resp, "status", json_object_new_string("ERROR"));
                    json_object_object_add(final_resp, "message", json_object_new_string("文件传输错误：MD5校验不匹配，请重新上传。"));
                }
                if (received_md5) free(received_md5);
                send_response(cli->sock, final_resp);
                json_object_put(final_resp);
            }
        } else if (status_str && strcmp(status_str, "PROCEED_DOWNLOAD") == 0) {
            const char* filename = json_object_get_string(json_object_object_get(req, "filename"));
            long long filesize = json_object_get_int64(json_object_object_get(resp, "filesize"));
            char filepath[512];
            sprintf(filepath, "%s/%s", STORAGE_DIR, filename);

            if (send_file(cli->sock, filepath) == 0) {
                pthread_mutex_lock(&db_mutex);
                char sql[512];
                sprintf(sql, "UPDATE server_files SET download_count = download_count + 1 WHERE filename = '%s';", filename);
                sqlite3_exec(db, sql, 0, 0, NULL);
                char user_download_table[100];
                sprintf(user_download_table, "user_downloads_%d", cli->user_id);
                char create_table_sql[256];
                sprintf(create_table_sql, "CREATE TABLE IF NOT EXISTS %s (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, filesize INTEGER, download_time DATETIME DEFAULT CURRENT_TIMESTAMP);", user_download_table);
                sqlite3_exec(db, create_table_sql, 0, 0, NULL);
                sprintf(sql, "INSERT INTO %s (filename, filesize) VALUES ('%s', %lld);", user_download_table, filename, filesize);
                sqlite3_exec(db, sql, 0, 0, NULL);
                pthread_mutex_unlock(&db_mutex);
            } else {
                fprintf(stderr, "发送文件 %s 到客户端 %s 失败\n", filename, cli->username);
            }
        }
        
        if (status_str && strcmp(cmd, "DELETE_ACCOUNT") == 0 && strcmp(status_str, "SUCCESS") == 0) {
            json_object_put(req);
            json_object_put(resp);
            break; 
        }

        json_object_put(req);
        json_object_put(resp);
    }
    close(cli->sock);
    remove_client(cli->sock);
    pthread_detach(pthread_self());
}
