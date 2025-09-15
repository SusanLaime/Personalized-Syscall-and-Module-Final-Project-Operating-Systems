#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>

#define __NR_pidfiles 548

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    pid_t pid = (pid_t)atoi(argv[1]);
    char buf[4096];

    long ret = syscall(__NR_pidfiles, pid, buf, sizeof(buf));
    if (ret < 0) {
        perror("syscall(pidfiles)");
        return 1;
    }

    printf("Returned: %ld\nOutput:\n%s\n", ret, buf);
    return 0;
}
