#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <fnmatch.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#define MAX_ROW 100
#define CONFIG_PATH "config.txt"
#define MAX_FILENAME_LENGTH 128
#define MAX_IP_NUM 100
#define MAX_PATH_LENGTH 128

enum command {
    OPEN,
    READ,
    WRITE,
    CONNECT,
    ADDR,
    COUNT
};

char *blacklist[COUNT][MAX_ROW] = {0};
int blacklistLen[COUNT] = {0};
char *ip[MAX_IP_NUM] = {0};
int ip_count = 0;

static int flag = 0;

void free_blacklists() {
    for (int i = 0; i < COUNT; i++) {
        for (int j = 0; j < blacklistLen[i]; j++) {
            free(blacklist[i][j]);
        }
        blacklistLen[i] = 0;
    }
}

int parse_blacklists(const char *filename) {
    static FILE *(*original_fopen)(const char *, const char *) = NULL;
    if (!original_fopen) {
        original_fopen = dlsym(RTLD_NEXT, "fopen");
    }
    FILE *file = original_fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        return -1;
    }


    char line[256];
    int current_list = -1;
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "BEGIN")) {
            if (strstr(line, "open-blacklist")) current_list = 0;
            else if (strstr(line, "read-blacklist")) current_list = 1;
            else if (strstr(line, "write-blacklist")) current_list = 2;
            else if (strstr(line, "connect-blacklist")) current_list = 3;
            else if (strstr(line, "getaddrinfo-blacklist")) current_list = 4;
        } else if (strstr(line, "END")) {
            current_list = -1;
        } else if (current_list != -1) {
            line[strcspn(line, "\n")] = 0;  // Remove newline character
            char *entry = strdup(line);
            if (!entry) {
                perror("Failed to allocate memory");
                fclose(file);
                return -1;
            }
            blacklist[current_list][blacklistLen[current_list]++] = entry;
        }
    }

    fclose(file);
    atexit(free_blacklists);
    return 0;
}

int is_blacklisted(const char *blockedItem, int command) {
    // printf("Command: %d\nBlack len: %d\n", command, blacklistLen[command]);
    if(command == READ) {
        for(int i = 0; i < blacklistLen[command]; i++) {
            // printf("Black inspect: %s\n", blacklist[command][i]);
            // printf("Target: %s\n", blockedItem);
            if (strstr(blockedItem, blacklist[command][i]) != NULL) {
                // printf("find: %s\n", blockedItem);
                return 1;
            }
        }
    } else {
        for(int i = 0; i < blacklistLen[command]; i++) {
            // printf("Black inspect: %s\n", blacklist[command][i]);
            // printf("Target: %s\n", blockedItem);
            if (fnmatch(blacklist[command][i], blockedItem, FNM_PATHNAME) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

void get_path(FILE *stream, char *filename) {
    // 獲取文件描述符
    int fd = fileno(stream);
    if (fd == -1) {
        perror("fileno");
    }

    // 構建文件描述符的路徑
    char proc_path[MAX_PATH_LENGTH];
    snprintf(proc_path, MAX_PATH_LENGTH, "/proc/self/fd/%d", fd);

    // 讀取符號鏈接的目標文件名稱
    char target_path[MAX_PATH_LENGTH];
    ssize_t target_length = readlink(proc_path, target_path, sizeof(target_path) - 1);
    if (target_length == -1) {
        perror("readlink");
    }

    // 添加結束符
    target_path[target_length] = '\0';
    strcpy(filename, target_path);
}

void get_filename_from_stream(FILE *stream, char *filename) {
    // 獲取文件描述符
    int fd = fileno(stream);
    if (fd == -1) {
        perror("fileno");
    }

    // 構建文件描述符的路徑
    char proc_path[MAX_PATH_LENGTH];
    snprintf(proc_path, MAX_PATH_LENGTH, "/proc/self/fd/%d", fd);

    // 讀取符號鏈接的目標文件名稱
    char target_path[MAX_PATH_LENGTH];
    ssize_t target_length = readlink(proc_path, target_path, sizeof(target_path) - 1);
    if (target_length == -1) {
        perror("readlink");
    }

    // 添加結束符
    target_path[target_length] = '\0';
    char *temp = strrchr(target_path, '/');
    strcpy(filename, temp+1);
}



FILE *fopen(const char *path, const char *mode) {
    if(flag == 0) {
        parse_blacklists(CONFIG_PATH);
        // printf("Open\n");
        // for(int i = 0; i < COUNT; i++) {
        //     for(int j = 0; j < blacklistLen[i]; j++) {
        //         printf("%s\n", blacklist[i][j]);
        //     }
        // }
        // for(int i = 0; i < COUNT; i++) {
        //     printf("%d\n", blacklistLen[i]);
        // }
        flag = 1;
    }
    static FILE *(*original_fopen)(const char *, const char *) = NULL;
    if (!original_fopen) {
        original_fopen = dlsym(RTLD_NEXT, "fopen");
    }

    // 檢查檔案是否為 symbolic link
    struct stat file_stat;
    if (lstat(path, &file_stat) == 0 && S_ISLNK(file_stat.st_mode)) {
        // 取得 symbolic link 的目標檔案路徑
        char target_path[MAX_PATH_LENGTH];
        ssize_t len = readlink(path, target_path, sizeof(target_path) - 1);
        if (len != -1) {
            target_path[len] = '\0';
            // 檢查 symbolic link 的目標檔案是否在黑名單中
            if (is_blacklisted(target_path, OPEN)) {
                fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = 0x0 (symbolic link to blacklisted file: %s)\n", path, mode, target_path);
                errno = EACCES;
                return NULL;
            }
        }
    }

    FILE *fp = original_fopen(path, mode);
    if (is_blacklisted(path, OPEN)) {
        fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = 0x0\n", path, mode);
        errno = EACCES;
        return NULL;
    } else {
        fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", path, mode, fp);
        return fp;
    }
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if(flag == 0) {
        parse_blacklists(CONFIG_PATH);
        flag = 1;
    }
    static FILE *(*original_fopen)(const char *, const char *) = NULL;
    if (!original_fopen) {
        original_fopen = dlsym(RTLD_NEXT, "fopen");
    }
    static size_t (*original_fread)(void *, size_t, size_t, FILE *) = NULL;
    if (!original_fread) {
        original_fread = dlsym(RTLD_NEXT, "fread");
    }
    static size_t (*original_fwrite)(const void *, size_t, size_t, FILE *) = NULL;
    if (!original_fwrite) {
        original_fwrite = dlsym(RTLD_NEXT, "fwrite");
    }
    int result;
    void *buf = malloc(size * nmemb);
    result = original_fread(buf, size, nmemb, stream);
    // printf("To be read: %s\n", (const char *)ptr);
    if (is_blacklisted((const char *)buf, READ)) {
        errno = EACCES;
        result = 0;
    } else {
        memcpy(ptr, buf, size * nmemb);
    }
    free(buf);
    // result = original_fread(ptr, size, nmemb, stream);

    fprintf(stderr, "[logger] fread(%p, %ld, %ld, %p) = %d\n", ptr, size, nmemb, stream, result);

    char filename[MAX_FILENAME_LENGTH];
    get_filename_from_stream(stream, filename);
    if (filename == NULL) {
        fprintf(stderr, "Failed to get filename\n");
        return 1;
    }
    char new_filename[MAX_FILENAME_LENGTH + 64];
    sprintf(new_filename, "%d-%s-read.log", getpid(), filename);
    FILE *log_file = original_fopen(new_filename, "a");
    if (!log_file) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
    }
    original_fwrite(ptr, size, result, log_file);
    fclose(log_file);
    return result;
}

char *escape_string(const char *str) {
    size_t len = strlen(str);
    char *escaped_str = (char *)malloc((len * 2 + 1) * sizeof(char)); // 分配足夠的記憶體，每個特殊字符需要兩個字符空間
    if (!escaped_str) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    char *p = escaped_str;
    for (; *str != '\0'; str++) {
        switch (*str) {
            case '\"':
                *p++ = '\\';
                *p++ = '\"';
                break;
            case '\'':
                *p++ = '\\';
                *p++ = '\'';
                break;
            case '\n':
                *p++ = '\\';
                *p++ = 'n';
                break;
            default:
                *p++ = *str;
                break;
        }
    }
    *p = '\0'; // 確保輸出字串以 null 結尾
    return escaped_str;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if(flag == 0) {
        parse_blacklists(CONFIG_PATH);
        flag = 1;
    }
    static FILE *(*original_fopen)(const char *, const char *) = NULL;
    if (!original_fopen) {
        original_fopen = dlsym(RTLD_NEXT, "fopen");
    }
    static size_t (*original_fwrite)(const void *, size_t, size_t, FILE *) = NULL;
    if (!original_fwrite) {
        original_fwrite = dlsym(RTLD_NEXT, "fwrite");
    }

    char filepath[MAX_FILENAME_LENGTH];
    get_path(stream, filepath);
    if (filepath == NULL) {
        fprintf(stderr, "Failed to get filepath\n");
        return 1;
    }

    int result;
    // printf("Write filepath: %s\n", filepath);
    if (is_blacklisted(filepath, WRITE)) {
        // printf("Write black\n");
        result = 0;
        errno = EACCES;
    } else {
        result = original_fwrite(ptr, size, nmemb, stream);
    }

    char *escaped_str = escape_string((char *)ptr);

    fprintf(stderr, "[logger] fwrite(\"%s\", %ld, %ld, %p) = %d\n", escaped_str, size, nmemb, stream, result);
    free(escaped_str);

    // Log content to log file
    char filename[MAX_FILENAME_LENGTH];
    get_filename_from_stream(stream, filename);
    if (filename == NULL) {
        fprintf(stderr, "Failed to get filename\n");
        return 1;
    }
    char new_filename[MAX_FILENAME_LENGTH + 64];
    sprintf(new_filename, "%d-%s-write.log", getpid(), filename);
    FILE *log_file = original_fopen(new_filename, "a");
    if (!log_file) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
    }
    original_fwrite(ptr, size, result, log_file);
    fclose(log_file);

    return result;
}

void free_ip() {
    for(int i = 0; i < ip_count; i++) {
        free(ip[i]);
        ip[i] = NULL;
    }
}

char *cast_ipv4_address(const struct sockaddr *addr) {
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *addr_in = (const struct sockaddr_in *)addr;
        ip[ip_count] = malloc(sizeof(char) * INET_ADDRSTRLEN);
        if(ip_count == 0) {
            atexit(free_ip);
        }
        if (inet_ntop(AF_INET, &addr_in->sin_addr, ip[ip_count], sizeof(ip))) {
            return ip[ip_count++];
        } else {
            perror("inet_ntop failed");
        }
    }
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if(flag == 0) {
        parse_blacklists(CONFIG_PATH);
        flag = 1;
    }
    int (*original_connect)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "connect");
    char *ip = cast_ipv4_address(addr);
    int result = 0;
    if(is_blacklisted(ip, CONNECT)) {
        errno = ECONNREFUSED;
        result = -1;
    } else {
        result = original_connect(sockfd, addr, addrlen);
    }
    fprintf(stderr, "[logger] connect(%d, \"%s\", %d) = %d\n", sockfd, ip, addrlen, result);
    return result;
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    if(flag == 0) {
        parse_blacklists(CONFIG_PATH);
        flag = 1;
    }
    int (*original_getaddrinfo)(const char *node, const char *service,
                                const struct addrinfo *hints,
                                struct addrinfo **res) = dlsym(RTLD_NEXT, "getaddrinfo");
    int result = original_getaddrinfo(node, service, hints, res);
    if(is_blacklisted(node, ADDR)) {
        result = EAI_NONAME;
    }
    fprintf(stderr, "[logger] getaddrinfo(\"%s\", \"%s\", %p, %p) = %d\n", node, service, hints, res, result);
    return result;
}

int system(const char *command) {
    static int (*original_system)(const char *) = NULL;
    if (!original_system) {
        original_system = dlsym(RTLD_NEXT, "system");
    }
    int result = original_system(command);
    fprintf(stderr, "[logger] system(\"%s\") = %d\n", command, result);
    return result;
}