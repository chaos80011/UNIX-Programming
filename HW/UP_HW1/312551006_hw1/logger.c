#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    int opt;
    char *outputFile = NULL;
    char *soPath = "./lib.so"; // 預設.so檔的路徑

    extern char *optarg;
    extern int optind;

    // 使用getopt來解析命令行參數
    while ((opt = getopt(argc, argv, "o:p:")) != -1) {
        switch (opt) {
            case 'o':
                outputFile = optarg;
                break;
            case 'p':
                soPath = optarg;
                break;
            default: // 未知的選項
                fprintf(stderr, "Usage: %s [-o file] [-p sopath] command [arg1 arg2 ...]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Expected command after options\n");
        exit(EXIT_FAILURE);
    }

    // 設置LD_PRELOAD環境變量
    setenv("LD_PRELOAD", soPath, 1);

    // 若指定了輸出文件，則將stderr重定向到該文件
    if (outputFile) {
        FILE *fp = freopen(outputFile, "w", stderr);
        if (fp == NULL) {
            perror("Failed to redirect stderr");
            exit(EXIT_FAILURE);
        }
    }

    // 透過execvp執行command
    char **args = &argv[optind+1];
    execvp(args[0], args);
    perror("Failed to exec the program");
    return 1;
}