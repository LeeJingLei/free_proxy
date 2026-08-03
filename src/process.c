#include "free_proxy.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int ensure_runtime_dir(void) {
    if (mkdir(FP_RUNTIME_DIR, 0755) == -1 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

pid_t fp_read_pid(void) {
    FILE *file;
    long pid;

    file = fopen(FP_PID_PATH, "r");
    if (file == NULL) {
        return -1;
    }
    if (fscanf(file, "%ld", &pid) != 1 || pid <= 1) {
        fclose(file);
        return -1;
    }
    fclose(file);
    return (pid_t)pid;
}

int fp_write_pid(void) {
    FILE *file;

    if (ensure_runtime_dir() != 0) {
        return -1;
    }
    file = fopen(FP_PID_PATH, "w");
    if (file == NULL) {
        return -1;
    }
    if (fprintf(file, "%ld\n", (long)getpid()) < 0 || fclose(file) != 0) {
        return -1;
    }
    return 0;
}

void fp_remove_pid(void) {
    (void)unlink(FP_PID_PATH);
}

int fp_start_daemon(const char *program_path) {
    pid_t pid;

    pid = fp_read_pid();
    if (pid > 1) {
        if (kill(pid, 0) == 0 || errno == EPERM) {
            return 0;
        }
        if (errno == ESRCH) {
            fp_remove_pid();
        } else {
            return -1;
        }
    }
    pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        if (setsid() < 0) {
            _exit(127);
        }
        if (freopen("/dev/null", "w", stdout) == NULL ||
            freopen("/dev/null", "w", stderr) == NULL) {
            _exit(127);
        }
        execl(program_path, program_path, "run", (char *)NULL);
        _exit(127);
    }
    return 0;
}

int fp_stop_daemon(void) {
    pid_t pid = fp_read_pid();

    if (pid <= 1) {
        fp_remove_pid();
        return 0;
    }
    if (kill(pid, SIGTERM) != 0 && errno != ESRCH) {
        return -1;
    }
    fp_remove_pid();
    return 0;
}
