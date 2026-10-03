#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <libgen.h>

int main(int argc, char **argv) {
    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n < 0) {
        perror("readlink");
        return 1;
    }
    exe[n] = '\0';

    char core[PATH_MAX];
    snprintf(core, sizeof(core), "%s/lib/core.pyc", dirname(exe));

    if (access(core, R_OK) != 0) {
        fprintf(stderr, "[X] lib/core.pyc tidak ditemukan.\n");
        return 1;
    }

    char **args = calloc((size_t)argc + 3, sizeof(char *));
    if (!args) {
        perror("calloc");
        return 1;
    }
    args[0] = "python";
    args[1] = core;
    for (int i = 1; i < argc; i++) {
        args[i + 1] = argv[i];
    }

    execvp("python", args);
    perror("python");
    return 1;
}
