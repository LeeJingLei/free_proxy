#include "free_proxy.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int ensure_runtime_dir(void) {
    if (mkdir(FP_RUNTIME_DIR, 0755) == -1 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static int read_process_record(pid_t *pid, unsigned long long *start_time,
                               struct fp_config *config) {
    FILE *file;
    long parsed_pid;
    char address[INET_ADDRSTRLEN];
    unsigned int port;

    file = fopen(FP_PID_PATH, "r");
    if (file == NULL) {
        return -1;
    }
    if (fscanf(file, "%ld %llu %15s %u", &parsed_pid, start_time, address, &port) != 4 ||
        parsed_pid <= 1 || port > 65535 || inet_pton(AF_INET, address, &config->proxy_addr) != 1) {
        fclose(file);
        return -1;
    }
    fclose(file);
    config->proxy_port = (unsigned short)port;
    *pid = (pid_t)parsed_pid;
    return 0;
}

static int process_start_time(pid_t pid, unsigned long long *start_time) {
    char path[64];
    char line[1024];
    char *cursor;
    char *token;
    char *save = NULL;
    FILE *file;
    int field = 3;

    if (snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) < 0) {
        return -1;
    }
    file = fopen(path, "r");
    if (file == NULL || fgets(line, sizeof(line), file) == NULL) {
        if (file != NULL) {
            fclose(file);
        }
        return -1;
    }
    fclose(file);
    cursor = strrchr(line, ')');
    if (cursor == NULL || cursor[1] != ' ') {
        return -1;
    }
    cursor += 2;
    for (token = strtok_r(cursor, " ", &save); token != NULL;
         token = strtok_r(NULL, " ", &save), ++field) {
        if (field == 22) {
            char *end = NULL;
            errno = 0;
            *start_time = strtoull(token, &end, 10);
            return errno == 0 && end != token ? 0 : -1;
        }
    }
    return -1;
}

static int exe_is_free_proxy(const char *target) {
    const char *binary_name = strrchr(target, '/');

    if (binary_name == NULL) {
        binary_name = target;
    } else {
        ++binary_name;
    }
    return strcmp(binary_name, "free_proxy") == 0 ||
           strcmp(binary_name, "free_proxy (deleted)") == 0;
}

static int cmdline_is_run(pid_t pid) {
    char command_path[64];
    char command[256];
    ssize_t command_length;
    size_t first_argument_length;
    int command_fd;

    if (snprintf(command_path, sizeof(command_path), "/proc/%ld/cmdline", (long)pid) < 0) {
        return 0;
    }
    command_fd = open(command_path, O_RDONLY);
    if (command_fd < 0) {
        return 0;
    }
    command_length = read(command_fd, command, sizeof(command) - 1);
    close(command_fd);
    if (command_length <= 0) {
        return 0;
    }
    first_argument_length = strnlen(command, (size_t)command_length);
    if (first_argument_length + 1 >= (size_t)command_length) {
        return 0;
    }
    return strcmp(command + first_argument_length + 1, "run") == 0;
}

static int process_is_ours(pid_t pid, unsigned long long expected_start_time) {
    char process_path[64];
    char target[4096];
    char self[4096];
    ssize_t target_length;
    ssize_t self_length;
    unsigned long long actual_start_time;

    if (process_start_time(pid, &actual_start_time) != 0 || actual_start_time != expected_start_time ||
        snprintf(process_path, sizeof(process_path), "/proc/%ld/exe", (long)pid) < 0) {
        return 0;
    }
    target_length = readlink(process_path, target, sizeof(target) - 1);
    if (target_length < 0) {
        return 0;
    }
    target[target_length] = '\0';
    if (!exe_is_free_proxy(target) || !cmdline_is_run(pid)) {
        return 0;
    }
    self_length = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (self_length >= 0) {
        self[self_length] = '\0';
        if (strcmp(target, self) == 0) {
            return 1;
        }
    }
    /* Accept path-mismatched or deleted binaries that still look like our daemon. */
    return 1;
}

static int is_legacy_daemon(pid_t pid) {
    char process_path[64];
    char status_path[64];
    char target[4096];
    char line[256];
    ssize_t target_length;
    FILE *file;
    pid_t ppid = 0;

    if (snprintf(process_path, sizeof(process_path), "/proc/%ld/exe", (long)pid) < 0 ||
        snprintf(status_path, sizeof(status_path), "/proc/%ld/status", (long)pid) < 0) {
        return 0;
    }
    target_length = readlink(process_path, target, sizeof(target) - 1);
    if (target_length < 0) {
        return 0;
    }
    target[target_length] = '\0';
    if (!exe_is_free_proxy(target) || !cmdline_is_run(pid)) {
        return 0;
    }
    /*
     * Prefer session leaders (daemon started via setsid). Also accept PID 1 children
     * so systemd-managed instances are found even when they are not session leaders.
     * Client workers are neither session leaders nor direct children of init.
     */
    file = fopen(status_path, "r");
    if (file == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        if (sscanf(line, "PPid: %d", &ppid) == 1) {
            break;
        }
    }
    fclose(file);
    if (getsid(pid) == pid && getpgid(pid) == pid) {
        return 1;
    }
    return ppid == 1;
}
static int stop_process(pid_t pid, unsigned long long start_time) {
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000000L};
    pid_t signal_target = pid;
    int attempts;

    if (getsid(pid) == pid && getpgid(pid) == pid) {
        signal_target = -pid;
    }
    if (kill(signal_target, SIGTERM) != 0 && errno != ESRCH) {
        return -1;
    }
    for (attempts = 0; attempts < FP_STOP_TIMEOUT_MS / 100; ++attempts) {
        unsigned long long actual_start_time;

        if ((signal_target < 0 && kill(signal_target, 0) != 0 && errno == ESRCH) ||
            (signal_target > 0 &&
             (process_start_time(pid, &actual_start_time) != 0 ||
              actual_start_time != start_time))) {
            return 0;
        }
        (void)waitpid(pid, NULL, WNOHANG);
        nanosleep(&delay, NULL);
    }
    if (kill(signal_target, SIGKILL) != 0 && errno != ESRCH) {
        return -1;
    }
    for (attempts = 0; attempts < 10; ++attempts) {
        unsigned long long actual_start_time;

        if ((signal_target < 0 && kill(signal_target, 0) != 0 && errno == ESRCH) ||
            (signal_target > 0 &&
             (process_start_time(pid, &actual_start_time) != 0 ||
              actual_start_time != start_time))) {
            return 0;
        }
        nanosleep(&delay, NULL);
    }
    return -1;
}

static int stop_untracked_daemons(void) {
    DIR *directory = opendir("/proc");
    struct dirent *entry;

    if (directory == NULL) {
        return -1;
    }
    while ((entry = readdir(directory)) != NULL) {
        char *end = NULL;
        long value;
        unsigned long long start_time;

        if (!isdigit((unsigned char)entry->d_name[0])) {
            continue;
        }
        errno = 0;
        value = strtol(entry->d_name, &end, 10);
        if (errno != 0 || *end != '\0' || value <= 1 ||
            !is_legacy_daemon((pid_t)value) ||
            process_start_time((pid_t)value, &start_time) != 0) {
            continue;
        }
        if (stop_process((pid_t)value, start_time) != 0) {
            closedir(directory);
            return -1;
        }
    }
    closedir(directory);
    return 0;
}

static int listener_is_released(void) {
    int listener;
    int option = 1;
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(FP_LISTEN_PORT),
    };

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        return -1;
    }
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) != 0 ||
        bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(listener);
        return -1;
    }
    close(listener);
    return 0;
}

static int wait_listener_released(void) {
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000000L};
    int attempts;

    for (attempts = 0; attempts < 50; ++attempts) {
        if (listener_is_released() == 0) {
            return 0;
        }
        nanosleep(&delay, NULL);
    }
    return -1;
}

pid_t fp_read_pid(void) {
    pid_t pid;
    unsigned long long start_time;
    struct fp_config config;

    return read_process_record(&pid, &start_time, &config) == 0 ? pid : -1;
}

int fp_write_pid(const struct fp_config *config) {
    FILE *file;
    unsigned long long start_time;
    char address[INET_ADDRSTRLEN];

    if (ensure_runtime_dir() != 0) {
        return -1;
    }
    if (process_start_time(getpid(), &start_time) != 0 ||
        inet_ntop(AF_INET, &config->proxy_addr, address, sizeof(address)) == NULL) {
        return -1;
    }
    file = fopen(FP_PID_PATH, "w");
    if (file == NULL) {
        return -1;
    }
    if (fprintf(file, "%ld %llu %s %u\n", (long)getpid(), start_time, address,
                config->proxy_port) < 0 ||
        fclose(file) != 0) {
        return -1;
    }
    return 0;
}

void fp_remove_pid(void) {
    (void)unlink(FP_PID_PATH);
}

int fp_lock_acquire(void) {
    int file_descriptor;

    if (ensure_runtime_dir() != 0) {
        return -1;
    }
    file_descriptor = open(FP_LOCK_PATH, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (file_descriptor < 0 || flock(file_descriptor, LOCK_EX) != 0) {
        if (file_descriptor >= 0) {
            close(file_descriptor);
        }
        return -1;
    }
    return file_descriptor;
}

void fp_lock_release(int lock_fd) {
    if (lock_fd >= 0) {
        (void)flock(lock_fd, LOCK_UN);
        (void)close(lock_fd);
    }
}

bool fp_daemon_matches_config(const struct fp_config *config) {
    pid_t pid;
    unsigned long long start_time;
    struct fp_config running_config;

    return read_process_record(&pid, &start_time, &running_config) == 0 &&
           process_is_ours(pid, start_time) &&
           running_config.proxy_port == config->proxy_port &&
           running_config.proxy_addr.s_addr == config->proxy_addr.s_addr;
}

int fp_start_daemon(const struct fp_config *config) {
    pid_t pid;
    int ready_pipe[2];
    struct pollfd ready_poll;
    char signal_byte;
    char executable[4096];
    ssize_t executable_length;
    char ready_fd_text[16];
    unsigned long long start_time;
    struct fp_config running_config;

    if (read_process_record(&pid, &start_time, &running_config) == 0) {
        if (process_is_ours(pid, start_time) &&
            running_config.proxy_port == config->proxy_port &&
            running_config.proxy_addr.s_addr == config->proxy_addr.s_addr) {
            return 0;
        }
        if (fp_stop_daemon() != 0) {
            return -1;
        }
    } else if (stop_untracked_daemons() != 0) {
        return -1;
    }
    fp_remove_pid();
    fp_stats_unlink();
    executable_length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    if (executable_length < 0 || pipe2(ready_pipe, O_CLOEXEC) != 0) {
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        return -1;
    }
    if (pid == 0) {
        executable[executable_length] = '\0';
        if (setsid() < 0) {
            _exit(127);
        }
        if (fcntl(ready_pipe[1], F_SETFD, 0) != 0 ||
            snprintf(ready_fd_text, sizeof(ready_fd_text), "%d", ready_pipe[1]) < 0) {
            _exit(127);
        }
        close(ready_pipe[0]);
        if (freopen("/dev/null", "w", stdout) == NULL ||
            freopen("/dev/null", "w", stderr) == NULL) {
            _exit(127);
        }
        execl(executable, executable, "run", "--ready-fd", ready_fd_text, (char *)NULL);
        _exit(127);
    }
    close(ready_pipe[1]);
    ready_poll = (struct pollfd){.fd = ready_pipe[0], .events = POLLIN};
    if (poll(&ready_poll, 1, FP_START_TIMEOUT_MS) <= 0 ||
        read(ready_pipe[0], &signal_byte, 1) != 1 || signal_byte != 'R') {
        (void)kill(pid, SIGTERM);
        (void)waitpid(pid, NULL, 0);
        close(ready_pipe[0]);
        return -1;
    }
    close(ready_pipe[0]);
    return 0;
}

int fp_stop_daemon(void) {
    pid_t pid;
    unsigned long long start_time;
    struct fp_config config;
    unsigned long long actual_start_time;

    if (read_process_record(&pid, &start_time, &config) == 0) {
        if (process_start_time(pid, &actual_start_time) == 0 && actual_start_time == start_time) {
            if (process_is_ours(pid, start_time)) {
                if (stop_process(pid, start_time) != 0) {
                    return -1;
                }
            }
            /* Stale or foreign PID with recycled identity: fall through to scan/cleanup. */
        }
    }
    if (stop_untracked_daemons() != 0) {
        return -1;
    }
    if (wait_listener_released() != 0) {
        /* Last resort: scan again in case a late restart grabbed the port. */
        if (stop_untracked_daemons() != 0 || wait_listener_released() != 0) {
            return -1;
        }
    }
    fp_remove_pid();
    fp_stats_unlink();
    return 0;
}
