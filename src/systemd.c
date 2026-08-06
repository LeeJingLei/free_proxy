#include "free_proxy.h"

#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#define FP_UNIT_PATH "/etc/systemd/system/free_proxy.service"
#define FP_INSTALLED_BINARY "/usr/local/bin/free_proxy"

static void silence_terminal(void) {
    if (freopen("/dev/null", "w", stdout) == NULL ||
        freopen("/dev/null", "w", stderr) == NULL) {
        _exit(127);
    }
}

static int systemctl_available(void) {
    return access("/bin/systemctl", X_OK) == 0 || access("/usr/bin/systemctl", X_OK) == 0;
}

static int run_systemctl(const char *action) {
    pid_t pid;
    int status;

    if (!systemctl_available()) {
        return -1;
    }
    pid = fork();
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
    pid_t pid;
    int status;

    if (!systemctl_available()) {
        return -1;
    }
    pid = fork();
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
    pid_t pid;
    int status;

    if (!systemctl_available() || access(FP_UNIT_PATH, R_OK) != 0) {
        return 0;
    }
    pid = fork();
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
    if (!fp_config_exists()) {
        return -1;
    }
    if (!systemctl_available()) {
        return -1;
    }
    if (access(FP_INSTALLED_BINARY, X_OK) != 0 || access(FP_UNIT_PATH, R_OK) != 0) {
        return -1;
    }
    return run_systemctl("enable");
}

int fp_autostart_disable(void) {
    if (!systemctl_available() || access(FP_UNIT_PATH, R_OK) != 0) {
        return 0;
    }
    if (run_systemctl("disable") == 0) {
        return 0;
    }
    /* Already disabled or unit unknown is fine for cleanup compatibility. */
    return fp_autostart_is_enabled() ? -1 : 0;
}

int fp_autostart_remove(void) {
    if (systemctl_available()) {
        (void)run_systemctl("disable");
        (void)run_systemctl("stop");
    }
    if (unlink(FP_UNIT_PATH) != 0 && errno != ENOENT && access(FP_UNIT_PATH, F_OK) == 0) {
        return -1;
    }
    if (systemctl_available()) {
        (void)reload_systemd();
    }
    return 0;
}
