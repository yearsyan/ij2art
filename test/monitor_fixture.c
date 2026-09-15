// Isolated syscall source for test/run-monitor.py; no app or injection needed.
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const unsigned calls = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 10) : 50000;
    const unsigned pause_us = argc > 2 ? (unsigned)strtoul(argv[2], NULL, 10) : 10000;
    printf("MONITOR_READY pid=%d\n", getpid());
    fflush(stdout);
    char go;
    if (read(STDIN_FILENO, &go, 1) != 1)
        return 2;
    for (unsigned i = 0; i < calls; ++i) {
        // O_CREAT is absent: this mode value is ignored by openat but gives each
        // raw tracepoint record a unique marker to detect replays after wrap.
        long fd = syscall(SYS_openat, (long)AT_FDCWD, "/dev/null",
                          (long)(O_RDONLY | O_CLOEXEC), (long)i);
        if (fd < 0 || close((int)fd))
            return 3;
        if (pause_us && i % 64 == 63)
            usleep(pause_us);
    }
    printf("MONITOR_DONE calls=%u\n", calls);
    fflush(stdout);
    _exit(0);
}
