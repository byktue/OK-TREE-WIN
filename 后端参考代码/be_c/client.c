#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <json-c/json.h>
#include <openssl/md5.h>
#include <sys/stat.h>
#include <libgen.h>

#define BUFFER_SIZE 4096
#define SERVER_IP "127.0.0.1"
#define PORT 8888
#define STORAGE_DIR "client_storage"

// 全局客户端状态
int sock;
int is_logged_in = 0, is_admin = 0, is_member = 0, user_id = -1;
char username[50];

void send_request(json_object *req);
json_object* receive_response();
char* calculate_file_md5(const char *filepath);
int receive_file(const char *filepath, long long filesize);
int send_file(const char *filepath);
void pre_login_menu();
void post_login_menu();
void handle_register();
void handle_login();
void handle_logout();
void handle_upload();
void handle_download();
void handle_search();
void handle_view_history(const char* type);
void handle_delete_history();
void handle_delete_account();
void handle_admin_set_member();
void handle_admin_delete_user();

void safe_exit(int status) {
    if(sock) close(sock);
    exit(status);
}

int main() {
    struct sockaddr_in server_addr;
    mkdir(STORAGE_DIR, 0777);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("无法创建套接字");
        return 1;
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(PORT);
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("连接服务器失败");
        close(sock);
        return 1;
    }
    printf("已连接到服务器。\n");
    while (1) {
        if (!is_logged_in) {
            pre_login_menu();
        } else {
            post_login_menu();
        }
    }
    close(sock);
    return 0;
}

void send_request(json_object *req) {
    const char *req_str = json_object_to_json_string(req);
    uint32_t len = htonl(strlen(req_str));
    if(write(sock, &len, sizeof(len)) < 0 || write(sock, req_str, strlen(req_str)) < 0){
        printf("发送请求失败，与服务器断开连接。\n");
        safe_exit(1);
    }
}

int read_all(void *buf, size_t len) {
    size_t bytes_read = 0;
    while (bytes_read < len) {
        ssize_t res = read(sock, (char*)buf + bytes_read, len - bytes_read);
        if (res <= 0) return -1;
        bytes_read += res;
    }
    return 0;
}

json_object* receive_response() {
    char buffer[BUFFER_SIZE];
    uint32_t len;
    if (read_all(&len, sizeof(len)) != 0) return NULL;
    len = ntohl(len);
    if (len >= BUFFER_SIZE) {
        fprintf(stderr, "服务器响应过大。\n");
        return NULL;
    }
    if (read_all(buffer, len) != 0) return NULL;
    buffer[len] = '\0';
    return json_tokener_parse(buffer);
}

char* calculate_file_md5(const char *filepath) {
    unsigned char c[MD5_DIGEST_LENGTH];
    FILE *inFile = fopen(filepath, "rb");
    MD5_CTX mdContext;
    int bytes;
    unsigned char data[1024];
    static char md5_str[MD5_DIGEST_LENGTH * 2 + 1];
    if (inFile == NULL) {
        printf("错误: 文件 %s 无法打开。\n", filepath);
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

int receive_file(const char *filepath, long long filesize) {
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

int send_file(const char *filepath) {
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

void clear_stdin() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void pre_login_menu() {
    printf("\n===== 欢迎使用模拟网盘 =====\n");
    printf("1. 登录\n");
    printf("2. 注册\n");
    printf("0. 退出\n");
    printf("请输入您的选择: ");
    int choice;
    if (scanf("%d", &choice) != 1) {
        clear_stdin();
        printf("无效输入，请输入数字。\n");
        return;
    }
    clear_stdin();
    switch (choice) {
        case 1: handle_login(); break;
        case 2: handle_register(); break;
        case 0: safe_exit(0);
        default: printf("无效选择。\n");
    }
}

void post_login_menu() {
    const char* role = is_admin ? "管理员" : (is_member ? "会员" : "普通用户");
    printf("\n===== 网盘菜单 (用户: %s, 身份: %s) =====\n", username, role);
    printf("1. 上传文件\n");
    printf("2. 下载文件\n");
    printf("3. 搜索服务器文件\n");
    printf("4. 查看我的上传\n");
    printf("5. 查看我的下载\n");
    printf("6. 管理我的上传和下载\n");
    printf("7. 注销我的账户\n");
    if (is_admin) {
        printf("------ 管理员面板 ------\n");
        printf("8. 设置/取消用户会员资格\n");
        printf("9. 删除用户账户\n");
    }
    printf("0. 登出\n");
    printf("请输入您的选择: ");
    int choice;
    if (scanf("%d", &choice) != 1) {
        clear_stdin();
        printf("无效输入，请输入数字。\n");
        return;
    }
    clear_stdin();
    switch (choice) {
        case 1: handle_upload(); break;
        case 2: handle_download(); break;
        case 3: handle_search(); break;
        case 4: handle_view_history("upload"); break;
        case 5: handle_view_history("download"); break;
        case 6: handle_delete_history(); break;
        case 7: handle_delete_account(); break;
        case 0: handle_logout(); break;
        default:
            if (is_admin && (choice == 8 || choice == 9)) {
                if (choice == 8) handle_admin_set_member();
                else handle_admin_delete_user();
            } else {
                 printf("无效选择。\n");
            }
    }
}

void handle_register() {
    char reg_user[50], reg_pass[50];
    printf("请输入注册用户名: ");
    scanf("%49s", reg_user);
    printf("请输入密码: ");
    scanf("%49s", reg_pass);
    clear_stdin();
    json_object *req = json_object_new_object();
    json_object_object_add(req, "command", json_object_new_string("REGISTER"));
    json_object_object_add(req, "username", json_object_new_string(reg_user));
    json_object_object_add(req, "password", json_object_new_string(reg_pass));
    send_request(req);
    json_object *resp = receive_response();
    if (!resp) { printf("与服务器断开连接。\n"); safe_exit(1); }
    printf("服务器响应: %s\n", json_object_get_string(json_object_object_get(resp, "message")));
    json_object_put(resp);
    json_object_put(req);
}

void handle_login() {
    char login_user[50], login_pass[50];
    printf("请输入用户名: ");
    scanf("%49s", login_user);
    printf("请输入密码: ");
    scanf("%49s", login_pass);
    clear_stdin();
    json_object *req = json_object_new_object();
    json_object_object_add(req, "command", json_object_new_string("LOGIN"));
    json_object_object_add(req, "username", json_object_new_string(login_user));
    json_object_object_add(req, "password", json_object_new_string(login_pass));
    send_request(req);
    json_object *resp = receive_response();
    if (!resp) { printf("与服务器断开连接。\n"); safe_exit(1); }
    const char *status = json_object_get_string(json_object_object_get(resp, "status"));
    if (strcmp(status, "SUCCESS") == 0) {
        is_logged_in = 1;
        user_id = json_object_get_int(json_object_object_get(resp, "user_id"));
        is_admin = json_object_get_int(json_object_object_get(resp, "is_admin"));
        is_member = json_object_get_int(json_object_object_get(resp, "is_member"));
        strcpy(username, json_object_get_string(json_object_object_get(resp, "username")));
        printf("登录成功。欢迎您, %s!\n", username);
    } else {
        printf("登录失败: %s\n", json_object_get_string(json_object_object_get(resp, "message")));
    }
    json_object_put(resp);
    json_object_put(req);
}

void handle_logout() {
    is_logged_in = 0; is_admin = 0; is_member = 0; user_id = -1;
    memset(username, 0, sizeof(username));
    printf("您已成功登出。\n");
}

void handle_upload() {
    char filepath[256];
    printf("请输入要上传文件的绝对路径或相对路径: ");
    scanf("%255s", filepath);
    clear_stdin();

    struct stat file_stat;
    if (stat(filepath, &file_stat) < 0) {
        perror("无法获取文件状态，请检查文件路径是否正确");
        return;
    }

    char *md5 = calculate_file_md5(filepath);
    if (!md5) return;
    
    char *fname = basename(filepath);
    
    json_object *req = json_object_new_object();
    json_object_object_add(req, "command", json_object_new_string("UPLOAD"));
    json_object_object_add(req, "filename", json_object_new_string(fname));
    json_object_object_add(req, "filesize", json_object_new_int64(file_stat.st_size));
    json_object_object_add(req, "md5", json_object_new_string(md5));
    
    send_request(req);
    json_object_put(req);

    json_object *resp1 = receive_response();
    if (!resp1) { 
        printf("与服务器断开连接。\n"); 
        safe_exit(1); 
    }
    
    const char *status = json_object_get_string(json_object_object_get(resp1, "status"));
    const char *message = json_object_get_string(json_object_object_get(resp1, "message"));
    printf("服务器响应: %s\n", message);
    
    if (strcmp(status, "PROCEED_UPLOAD") == 0) {
        printf("服务器准备就绪，开始文件传输...\n");
        if (send_file(filepath) == 0) {
            printf("文件数据已发送，等待服务器最终确认...\n");
            json_object *resp2 = receive_response();
            if (resp2) {
                printf("最终服务器响应: %s\n", json_object_get_string(json_object_object_get(resp2, "message")));
                json_object_put(resp2);
            } else {
                printf("在最终确认阶段与服务器断开连接。\n");
                json_object_put(resp1);
                safe_exit(1);
            }
        } else {
            printf("文件传输失败。\n");
        }
    }
    
    json_object_put(resp1);
}

void handle_download() {
    char filename[256];
    printf("请输入要下载的文件名: ");
    scanf("%255s", filename);
    clear_stdin();
    
    json_object *req = json_object_new_object();
    json_object_object_add(req, "command", json_object_new_string("DOWNLOAD"));
    json_object_object_add(req, "filename", json_object_new_string(filename));
    
    send_request(req);
    json_object_put(req);

    json_object *resp = receive_response();
    if (!resp) { 
        printf("与服务器断开连接。\n"); 
        safe_exit(1); 
    }
    
    const char *status = json_object_get_string(json_object_object_get(resp, "status"));
    const char *message = json_object_get_string(json_object_object_get(resp, "message"));
    printf("服务器响应: %s\n", message);
    
    if (strcmp(status, "PROCEED_DOWNLOAD") == 0) {
        long long filesize = json_object_get_int64(json_object_object_get(resp, "filesize"));
        char save_path[512];
        sprintf(save_path, "%s/%s", STORAGE_DIR, filename);
        printf("正在下载文件到 %s (大小: %lld 字节)...\n", save_path, filesize);
        
        if (receive_file(save_path, filesize) == 0) {
            printf("下载完成！\n");
        } else {
            printf("下载失败，连接中断。\n");
            remove(save_path);
        }
    }
    
    json_object_put(resp);
}

void handle_search() {
    char keyword[100];
    printf("请输入要搜索的文件名关键字: ");
    scanf("%99s", keyword);
    clear_stdin();
    json_object *req = json_object_new_object();
    json_object_object_add(req, "command", json_object_new_string("SEARCH"));
    json_object_object_add(req, "keyword", json_object_new_string(keyword));
    send_request(req);
    json_object *resp = receive_response();
    if (!resp) { printf("与服务器断开连接。\n"); json_object_put(req); safe_exit(1); }
    json_object *data = json_object_object_get(resp, "data");
    int count = json_object_array_length(data);
    printf("\n--- 搜索结果 (共 %d 条) ---\n", count);
    printf("%-30s | %-15s | %s\n", "文件名", "大小 (字节)", "下载次数");
    printf("----------------------------------------------------------\n");
    for (int i = 0; i < count; i++) {
        json_object *row = json_object_array_get_idx(data, i);
        printf("%-30s | %-15s | %s\n",
            json_object_get_string(json_object_object_get(row, "filename")),
            json_object_get_string(json_object_object_get(row, "filesize")),
            json_object_get_string(json_object_object_get(row, "download_count"))
        );
    }
    printf("----------------------------------------------------------\n");
    json_object_put(resp);
    json_object_put(req);
}

void handle_view_history(const char* type) {
    json_object *req = json_object_new_object();
    json_object_object_add(req, "command", json_object_new_string("VIEW_HISTORY"));
    json_object_object_add(req, "type", json_object_new_string(type));
    send_request(req);
    json_object *resp = receive_response();
    if (!resp) { printf("与服务器断开连接。\n"); json_object_put(req); safe_exit(1); }
    const char* type_cn = strcmp(type, "upload") == 0 ? "上传" : "下载";
    json_object *data = json_object_object_get(resp, "data");
    int count = json_object_array_length(data);
    printf("\n--- 我的%s记录 (共 %d 条) ---\n", type_cn, count);
    printf("%-5s | %-30s | %-15s | %s\n", "ID", "文件名", "大小 (字节)", "时间");
    printf("----------------------------------------------------------------------\n");
    for (int i = 0; i < count; i++) {
        json_object *row = json_object_array_get_idx(data, i);
        printf("%-5s | %-30s | %-15s | %s\n",
            json_object_get_string(json_object_object_get(row, "id")),
            json_object_get_string(json_object_object_get(row, "filename")),
            json_object_get_string(json_object_object_get(row, "filesize")),
            json_object_get_string(json_object_object_get(row, (strcmp(type, "upload") == 0 ? "upload_time" : "download_time")))
        );
    }
    printf("----------------------------------------------------------------------\n");
    json_object_put(resp);
    json_object_put(req);
}

// **重大修改**: handle_delete_history
void handle_delete_history() {
    char type_str[10];
    int record_id;
    printf("要管理哪种历史记录 (upload/download)? ");
    scanf("%9s", type_str);
    clear_stdin();
    if (strcmp(type_str, "upload") != 0 && strcmp(type_str, "download") != 0) {
        printf("类型无效，必须是 'upload' 或 'download'。\n");
        return;
    }
    printf("请输入要删除的记录ID，或输入-1删除全部: ");
    if (scanf("%d", &record_id) != 1) {
        clear_stdin();
        printf("无效输入，请输入数字。\n");
        return;
    }
    clear_stdin();
    
    json_object *req = json_object_new_object();
    json_object_object_add(req, "command", json_object_new_string("DELETE_HISTORY"));
    json_object_object_add(req, "type", json_object_new_string(type_str));
    json_object_object_add(req, "record_id", json_object_new_int(record_id));
    
    send_request(req);
    json_object_put(req);

    json_object *resp = receive_response();
    if (!resp) { 
        printf("与服务器断开连接。\n"); 
        safe_exit(1); 
    }
    
    printf("服务器响应: %s\n", json_object_get_string(json_object_object_get(resp, "message")));
    
    // **新增逻辑**: 检查是否需要删除本地文件
    json_object *deleted_filename_obj;
    if (json_object_object_get_ex(resp, "deleted_filename", &deleted_filename_obj)) {
        const char *deleted_filename = json_object_get_string(deleted_filename_obj);
        printf("是否同时删除本地文件 '%s'? (y/n): ", deleted_filename);
        char choice;
        scanf(" %c", &choice);
        clear_stdin();
        if (choice == 'y' || choice == 'Y') {
            char local_filepath[512];
            sprintf(local_filepath, "%s/%s", STORAGE_DIR, deleted_filename);
            if (remove(local_filepath) == 0) {
                printf("本地文件 '%s' 删除成功。\n", deleted_filename);
            } else {
                perror("删除本地文件失败");
            }
        } else {
            printf("已保留本地文件。\n");
        }
    }
    
    json_object_put(resp);
}

void handle_delete_account() {
    char confirmation[10];
    printf("您确定要永久删除您的账户吗？此操作无法撤销。\n");
    printf("请输入 'YES' 确认: ");
    scanf("%9s", confirmation);
    clear_stdin();
    if (strcmp(confirmation, "YES") != 0) {
        printf("账户删除已取消。\n");
        return;
    }
    json_object *req = json_object_new_object();
    json_object_object_add(req, "command", json_object_new_string("DELETE_ACCOUNT"));
    send_request(req);
    json_object *resp = receive_response();
    if (!resp) { printf("与服务器断开连接。\n"); json_object_put(req); safe_exit(1); }
    printf("服务器响应: %s\n", json_object_get_string(json_object_object_get(resp, "message")));
    if (strcmp(json_object_get_string(json_object_object_get(resp, "status")), "SUCCESS") == 0) {
        handle_logout();
        printf("您将被返回到主菜单。\n");
    }
    json_object_put(resp);
    json_object_put(req);
}

void handle_admin_set_member() {
    char target_user[50];
    int status;
    printf("请输入要修改的用户名: ");
    scanf("%49s", target_user);
    printf("是否设为会员? (1 为是, 0 为否): ");
    if (scanf("%d", &status) != 1) {
        clear_stdin();
        printf("无效输入，请输入数字。\n");
        return;
    }
    clear_stdin();
    json_object *req = json_object_new_object();
    json_object_object_add(req, "command", json_object_new_string("ADMIN_SET_MEMBER"));
    json_object_object_add(req, "target_user", json_object_new_string(target_user));
    json_object_object_add(req, "is_member", json_object_new_int(status));
    send_request(req);
    json_object *resp = receive_response();
    if (!resp) { printf("与服务器断开连接。\n"); json_object_put(req); safe_exit(1); }
    printf("服务器响应: %s\n", json_object_get_string(json_object_object_get(resp, "message")));
    json_object_put(resp);
    json_object_put(req);
}

void handle_admin_delete_user() {
    char target_user[50];
    printf("请输入要删除的用户名: ");
    scanf("%49s", target_user);
    clear_stdin();
    char confirmation[10];
    printf("警告: 这将永久删除用户 '%s' 及其所有数据。请输入 'DELETE' 确认: ", target_user);
    scanf("%9s", confirmation);
    clear_stdin();
    if (strcmp(confirmation, "DELETE") != 0) {
        printf("删除用户操作已取消。\n");
        return;
    }
    json_object *req = json_object_new_object();
    json_object_object_add(req, "command", json_object_new_string("ADMIN_DELETE_USER"));
    json_object_object_add(req, "target_user", json_object_new_string(target_user));
    send_request(req);
    json_object *resp = receive_response();
    if (!resp) { printf("与服务器断开连接。\n"); json_object_put(req); safe_exit(1); }
    printf("服务器响应: %s\n", json_object_get_string(json_object_object_get(resp, "message")));
    json_object_put(resp);
    json_object_put(req);
}
