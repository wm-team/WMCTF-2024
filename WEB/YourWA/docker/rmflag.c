#ifndef _WIN32
// Unix
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    const char *filename = "flag.txt";

    // Set UID to 0 (root)
    if (setuid(0) != 0) {
        perror("setuid");
        exit(EXIT_FAILURE);
    }

    // Remove the file
    if (remove(filename) != 0) {
        perror("remove");
        exit(EXIT_FAILURE);
    }

    return 0;
}
#else
// Windows
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char filename[] = "flag.txt";

    // Try to delete the file
    if (!DeleteFile(filename)) {
        fprintf(stderr, "Failed to delete file: %lu\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    return 0;
}
#endif