#include "free_proxy.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

static int activate_proxy(const char *program_path, const struct fp_config *config) {
    if (fp_firewall_enable(config) != 0) {
        return -1;
    }
    if (fp_start_daemon(program_path) != 0) {
        (void)fp_firewall_disable();
        return -1;
    }
    return 0;
}

int fp_enable_proxy(const char *program_path, const char *proxy) {
    struct fp_config config;

    if (fp_parse_proxy(proxy, &config) != 0 || fp_config_save(&config) != 0) {
        return -1;
    }
    return activate_proxy(program_path, &config);
}

int fp_enable_saved_proxy(const char *program_path) {
    struct fp_config config;

    if (fp_config_load(&config) != 0) {
        return -1;
    }
    return activate_proxy(program_path, &config);
}

int fp_disable_proxy(void) {
    int firewall_result = fp_firewall_disable();
    int daemon_result = fp_stop_daemon();

    return firewall_result == 0 && daemon_result == 0 ? 0 : -1;
}

void fp_collect_status(struct fp_status *status) {
    struct fp_config config;

    memset(status, 0, sizeof(*status));
    status->config_present = fp_config_exists();
    status->daemon_pid = fp_read_pid();
    status->daemon_running =
        status->daemon_pid > 1 && kill(status->daemon_pid, 0) == 0;
    status->firewall_enabled = fp_firewall_is_enabled();
    status->autostart_enabled = fp_autostart_is_enabled();
    if (status->config_present && fp_config_load(&config) == 0 &&
        inet_ntop(AF_INET, &config.proxy_addr, status->proxy, INET_ADDRSTRLEN) != NULL) {
        size_t used = strlen(status->proxy);
        size_t available = sizeof(status->proxy) - used;
        int length = snprintf(status->proxy + used, available, ":%u",
                              config.proxy_port);
        status->config_valid = length > 0 && (size_t)length < available;
    }
}
