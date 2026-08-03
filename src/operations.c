#include "free_proxy.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define FP_INSTALLED_BINARY "/usr/local/bin/free_proxy"

static int activate_proxy_locked(const struct fp_config *config) {
    int result = -1;

    if (fp_daemon_matches_config(config) && fp_firewall_is_enabled(config)) {
        result = 0;
        return result;
    }
    if (fp_read_pid() > 1 && fp_stop_daemon() != 0) {
        return result;
    }
    if (fp_firewall_disable() != 0 || fp_start_daemon(config) != 0) {
        (void)fp_firewall_disable();
        return result;
    }
    return 0;
}

int fp_enable_proxy(const char *proxy) {
    struct fp_config config;
    struct fp_config previous_config;
    int lock_fd = fp_lock_acquire();
    bool had_previous_config;
    bool was_running;
    int result;

    if (lock_fd < 0 || fp_parse_proxy(proxy, &config) != 0) {
        fp_lock_release(lock_fd);
        return -1;
    }
    had_previous_config = fp_config_load(&previous_config) == 0;
    was_running = fp_read_pid() > 1;
    if (fp_config_save(&config) != 0) {
        fp_lock_release(lock_fd);
        return -1;
    }
    result = activate_proxy_locked(&config);
    if (result != 0 && had_previous_config) {
        (void)fp_config_save(&previous_config);
        if (was_running) {
            (void)activate_proxy_locked(&previous_config);
        }
    }
    fp_lock_release(lock_fd);
    return result;
}

int fp_enable_saved_proxy(void) {
    struct fp_config config;
    int lock_fd = fp_lock_acquire();
    int result;

    if (lock_fd < 0 || fp_config_load(&config) != 0) {
        fp_lock_release(lock_fd);
        return -1;
    }
    result = activate_proxy_locked(&config);
    fp_lock_release(lock_fd);
    return result;
}

int fp_disable_proxy(void) {
    int lock_fd = fp_lock_acquire();
    int firewall_result;
    int daemon_result;

    if (lock_fd < 0) {
        return -1;
    }
    daemon_result = fp_stop_daemon();
    firewall_result = fp_firewall_disable();
    fp_lock_release(lock_fd);
    return firewall_result == 0 && daemon_result == 0 ? 0 : -1;
}

int fp_uninstall(void) {
    int lock_fd = fp_lock_acquire();
    int stop_result;
    int firewall_result;
    int service_result;

    if (lock_fd < 0) {
        return -1;
    }
    stop_result = fp_stop_daemon();
    firewall_result = fp_firewall_disable();
    service_result = fp_autostart_remove();
    fp_remove_pid();
    (void)unlink(FP_CONFIG_PATH);
    (void)unlink(FP_UI_LANGUAGE_PATH);
    fp_lock_release(lock_fd);
    (void)unlink(FP_LOCK_PATH);
    (void)rmdir(FP_RUNTIME_DIR);
    (void)rmdir(FP_CONFIG_DIR);
    if (unlink(FP_INSTALLED_BINARY) != 0 && access(FP_INSTALLED_BINARY, F_OK) == 0) {
        return -1;
    }
    return stop_result == 0 && firewall_result == 0 && service_result == 0 ? 0 : -1;
}

void fp_collect_status(struct fp_status *status) {
    struct fp_config config;

    memset(status, 0, sizeof(*status));
    status->config_present = fp_config_exists();
    status->daemon_pid = fp_read_pid();
    status->daemon_running =
        status->daemon_pid > 1 && kill(status->daemon_pid, 0) == 0;
    status->autostart_enabled = fp_autostart_is_enabled();
    if (status->config_present && fp_config_load(&config) == 0 &&
        inet_ntop(AF_INET, &config.proxy_addr, status->proxy, INET_ADDRSTRLEN) != NULL) {
        size_t used = strlen(status->proxy);
        size_t available = sizeof(status->proxy) - used;
        int length = snprintf(status->proxy + used, available, ":%u",
                              config.proxy_port);
        status->config_valid = length > 0 && (size_t)length < available;
        status->firewall_enabled = fp_firewall_is_enabled(&config);
    }
}
