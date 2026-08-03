#ifndef FREE_PROXY_H
#define FREE_PROXY_H

#include <netinet/in.h>
#include <stdbool.h>
#include <sys/types.h>

#define FP_CONFIG_DIR "/etc/free_proxy"
#define FP_CONFIG_PATH FP_CONFIG_DIR "/config"
#define FP_UI_LANGUAGE_PATH FP_CONFIG_DIR "/ui_language"
#define FP_RUNTIME_DIR "/run/free_proxy"
#define FP_PID_PATH FP_RUNTIME_DIR "/free_proxy.pid"
#define FP_CHAIN "FPROXY_OUT"
#define FP_LISTEN_PORT 12345

struct fp_config {
    struct in_addr proxy_addr;
    unsigned short proxy_port;
};

enum fp_ui_language {
    FP_UI_LANGUAGE_ZH,
    FP_UI_LANGUAGE_EN,
};

struct fp_status {
    bool config_present;
    bool config_valid;
    bool daemon_running;
    bool firewall_enabled;
    bool autostart_enabled;
    pid_t daemon_pid;
    char proxy[INET_ADDRSTRLEN + 7];
};

int fp_parse_proxy(const char *value, struct fp_config *config);
int fp_config_load(struct fp_config *config);
int fp_config_save(const struct fp_config *config);
bool fp_config_exists(void);
enum fp_ui_language fp_ui_language_load(void);
int fp_ui_language_save(enum fp_ui_language language);

int fp_firewall_enable(const struct fp_config *config);
int fp_firewall_disable(void);
int fp_firewall_is_enabled(void);

int fp_start_daemon(const char *program_path);
int fp_stop_daemon(void);
pid_t fp_read_pid(void);
int fp_write_pid(void);
void fp_remove_pid(void);

int fp_proxy_run(const struct fp_config *config);

int fp_autostart_enable(void);
int fp_autostart_disable(void);
int fp_autostart_is_enabled(void);

int fp_enable_proxy(const char *program_path, const char *proxy);
int fp_enable_saved_proxy(const char *program_path);
int fp_disable_proxy(void);
void fp_collect_status(struct fp_status *status);
int fp_tui_run(const char *program_path);

#endif
