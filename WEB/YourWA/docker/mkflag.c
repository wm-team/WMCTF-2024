#ifndef _WIN32
// Unix
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void print_usage(char *prog_name) {
    fprintf(stderr, "Usage: %s <user> [content]\n", prog_name);
    exit(EXIT_FAILURE);
}

int create_flag(const char *user, const char *filename, const char *content) {
    struct passwd *pwd = getpwnam(user);
    if (pwd == NULL) {
        perror("getpwnam");
        return -1;
    }

    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror("open");
        return -1;
    }

    if (content) {
        if (write(fd, content, strlen(content)) == -1) {
            perror("write");
            close(fd);
            return -1;
        }
    }

    close(fd);

    if (chown(filename, pwd->pw_uid, pwd->pw_gid) == -1) {
        perror("chown");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        print_usage(argv[0]);
    }

    char *user = argv[1];
    char *content = (argc == 3) ? argv[2] : NULL;
    const char *filename = "flag.txt";

    // Set UID to 0 (root)
    if (setuid(0) != 0) {
        perror("setuid");
        exit(EXIT_FAILURE);
    }

    int result = create_flag(user, filename, content);
    if (result != 0) {
        // Force open and write without getting UID
        int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd == -1) {
            perror("open");
            exit(EXIT_FAILURE);
        }

        if (content) {
            if (write(fd, content, strlen(content)) == -1) {
                perror("write");
                close(fd);
                exit(EXIT_FAILURE);
            }
        }

        close(fd);

        printf("File %s created\n", filename);
        if (content) {
            printf("Content written to %s\n", filename);
        }
    } else {
        printf("File %s created and ownership changed to %s\n", filename, user);
        if (content) {
            printf("Content written to %s\n", filename);
        }
    }

    return 0;
}
#else
// Windows
#include <accctrl.h>
#include <aclapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <windows.h>

void print_usage(char *prog_name) {
    fprintf(stderr, "Usage: %s <user> [content]\n", prog_name);
    exit(EXIT_FAILURE);
}

int create_and_set_owner(char *user, char *filename, char *content) {
    HANDLE hFile =
        CreateFile(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to create or open file: %lu\n", GetLastError());
        return -1;
    }

    if (content) {
        DWORD written;
        if (!WriteFile(hFile, content, strlen(content), &written, NULL)) {
            fprintf(stderr, "Failed to write to file: %lu\n", GetLastError());
            CloseHandle(hFile);
            return -1;
        }
    }

    CloseHandle(hFile);

    PSID pSid = NULL;
    SID_NAME_USE sidType;
    DWORD sidSize = 0, domainSize = 0;

    LookupAccountName(NULL, user, NULL, &sidSize, NULL, &domainSize, &sidType);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        fprintf(stderr, "Failed to get SID size: %lu\n", GetLastError());
        return -1;
    }

    pSid = (PSID)malloc(sidSize);
    char *domain = (char *)malloc(domainSize);

    if (!LookupAccountName(NULL, user, pSid, &sidSize, domain, &domainSize, &sidType)) {
        fprintf(stderr, "Failed to lookup account name: %lu\n", GetLastError());
        free(pSid);
        free(domain);
        return -1;
    }

    free(domain);

    if (SetNamedSecurityInfo(filename, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, pSid, NULL, NULL,
                             NULL) != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to set file owner: %lu\n", GetLastError());
        free(pSid);
        return -1;
    }

    free(pSid);

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        print_usage(argv[0]);
    }

    char *user = argv[1];
    char *content = (argc == 3) ? argv[2] : NULL;
    char filename[] = "flag.txt";

    int result = create_and_set_owner(user, filename, content);
    if (result != 0) {
        // Force open and write without setting owner
        HANDLE hFile = CreateFile(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "Failed to create or open file: %lu\n", GetLastError());
            exit(EXIT_FAILURE);
        }

        if (content) {
            DWORD written;
            if (!WriteFile(hFile, content, strlen(content), &written, NULL)) {
                fprintf(stderr, "Failed to write to file: %lu\n", GetLastError());
                CloseHandle(hFile);
                exit(EXIT_FAILURE);
            }
        }

        CloseHandle(hFile);

        printf("File %s created\n", filename);
        if (content) {
            printf("Content written to %s\n", filename);
        }
    } else {
        printf("File %s created and ownership changed to %s\n", filename, user);
        if (content) {
            printf("Content written to %s\n", filename);
        }
    }

    return 0;
}
#endif