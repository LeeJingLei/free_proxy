#include "free_proxy.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define FP_UNIT_PATH "/etc/systemd/system/free_proxy.service"
#define FP_INSTALLED_BINARY "/usr/local/bin/free_proxy"

static const char unit_contents[] =
    "[Unit]\n"
    "Description=free_proxy transparent SOCKS5 proxy\n"
    "After=network-online.target\n"
    "Wants=network-online.target\n"
    "\n"
    "[Service]\n"
    "Type=simple\n"
    "ExecStart=" FP_INSTALLED_BINARY " run\n"
    "Restart=on-failure\n"
    "RestartSec=2\n"
    "\n"
    "[Install]\n"
    "WantedBy=multi-user.target\n";

static void silence_terminal(void) {
    if (freopen("/dev/null", "w", stdout) == NULL ||
        freopen("/dev/null", "w", stderr) == NULL) {
        _exit(127);
    }
}

static int run_systemctl(const char *action) {
    pid_t pid = fork();
    int status;

    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        silence_terminal();
        execlp("systemctl", "systemctl", action, "free_proxy.service", (char *)NULL);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int reload_systemd(void) {
    pid_t pid = fork();
    int status;

    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        silence_terminal();
        execlp("systemctl", "systemctl", "daemon-reload", (char *)NULL);
        _exit(127);
    }
    return waitpid(pid, &status, 0) >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0
               ? 0
               : -1;
}

int fp_autostart_is_enabled(void) {
    pid_t pid = fork();
    int status;

    if (pid < 0) {
        return 0;
    }
    if (pid == 0) {
        silence_terminal();
        execlp("systemctl", "systemctl", "is-enabled", "--quiet", "free_proxy.service",
               (char *)NULL);
        _exit(127);
    }
    return waitpid(pid, &status, 0) >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int fp_autostart_enable(void) {
    FILE *unit_file;

    if (!fp_config_exists()) {
        return -1;
    }
    if (access(FP_INSTALLED_BINARY, X_OK) != 0) {
        return -1;
    }
    unit_file = fopen(FP_UNIT_PATH, "w");
    if (unit_file == NULL || fputs(unit_contents, unit_file) == EOF || fclose(unit_file) != 0) {
        return -1;
    }
    return reload_systemd() == 0 && run_systemctl("enable") == 0 ? 0 : -1;
}

int fp_autostart_disable(void) {
    int result = run_systemctl("disable");

    if (unlink(FP_UNIT_PATH) != 0 && access(FP_UNIT_PATH, F_OK) == 0) {
        return -1;
    }
    return reload_systemd() == 0 && result == 0 ? 0 : -1;
}
