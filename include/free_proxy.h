#ifndef FREE_PROXY_H
#define FREE_PROXY_H

#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/types.h>

#define FP_CONFIG_DIR "/etc/free_proxy"
#define FP_CONFIG_PATH FP_CONFIG_DIR "/config"
#define FP_UI_LANGUAGE_PATH FP_CONFIG_DIR "/ui_language"
#define FP_RUNTIME_DIR "/run/free_proxy"
#define FP_PID_PATH FP_RUNTIME_DIR "/free_proxy.pid"
#define FP_LOCK_PATH FP_RUNTIME_DIR "/lock"
#define FP_STATS_PATH FP_RUNTIME_DIR "/stats"
#define FP_CHAIN "FPROXY_OUT"
#define FP_LISTEN_PORT 12345
#define FP_START_TIMEOUT_MS 5000
#define FP_STOP_TIMEOUT_MS 5000
#define FP_CONNECT_TIMEOUT_MS 10000
#define FP_TEST_TIMEOUT_MS 3000
#define FP_TEST_SPEED_CONNECT_MS 5000
#define FP_TEST_SPEED_STALL_MS 10000
#define FP_TEST_SPEED_TOTAL_MS 60000
#define FP_TEST_SPEED_MAX_BYTES (10U * 1024U * 1024U)
#define FP_TEST_MAX_SITES 25
#define FP_TEST_MAX_SPEED 3
#define FP_TEST_FAILURES_SIZE 1024
#define FP_IO_TIMEOUT_MS 30000
#define FP_IDLE_TIMEOUT_MS 300000
#define FP_MAX_CLIENTS 128
#define FP_MAX_BYPASS 32
#define FP_BYPASS_TEXT_SIZE (FP_MAX_BYPASS * 20)

struct fp_bypass {
    struct in_addr network;
    unsigned char prefix;
    char text[INET_ADDRSTRLEN + 4];
};

struct fp_config {
    struct in_addr proxy_addr;
    unsigned short proxy_port;
    struct fp_bypass bypass[FP_MAX_BYPASS];
    size_t bypass_count;
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
    char bypass[FP_BYPASS_TEXT_SIZE];
};

enum fp_test_mode {
    FP_TEST_MODE_CONNECTIVITY,
    FP_TEST_MODE_LATENCY,
    FP_TEST_MODE_SPEED,
};

enum fp_test_phase {
    FP_TEST_PHASE_PREFLIGHT,
    FP_TEST_PHASE_CONNECTIVITY,
    FP_TEST_PHASE_LATENCY,
    FP_TEST_PHASE_SPEED,
    FP_TEST_PHASE_DONE,
};

enum fp_test_site_state {
    FP_TEST_SITE_PENDING,
    FP_TEST_SITE_RUNNING,
    FP_TEST_SITE_OK,
    FP_TEST_SITE_FAIL,
    FP_TEST_SITE_CANCELLED,
};

struct fp_test_site_result {
    char name[32];
    char domain[64];
    enum fp_test_site_state state;
    int latency_ms;
    double speed_bps;
    size_t bytes_downloaded;
};

struct fp_test_report {
    enum fp_test_mode mode;
    bool listener_ok;
    bool cancelled;
    struct fp_test_site_result sites[FP_TEST_MAX_SITES];
    size_t site_count;
    size_t sites_passed;
    struct fp_test_site_result speed[FP_TEST_MAX_SPEED];
    size_t speed_count;
    size_t speed_passed;
    double best_speed_bps;
    char failures[FP_TEST_FAILURES_SIZE];
};

struct fp_test_progress_event {
    enum fp_test_phase phase;
    size_t index;
    size_t total;
    enum fp_test_site_state state;
    int latency_ms;
    double speed_bps;
    size_t bytes_downloaded;
    char name[32];
    char domain[64];
};

typedef void (*fp_test_event_callback)(const struct fp_test_progress_event *event, void *context);

#define FP_DIAGNOSTIC_STEP_COUNT 9

enum fp_diagnostic_step {
    FP_DIAGNOSTIC_CONFIG,
    FP_DIAGNOSTIC_DAEMON,
    FP_DIAGNOSTIC_LISTENER,
    FP_DIAGNOSTIC_FIREWALL,
    FP_DIAGNOSTIC_PROXY_TCP,
    FP_DIAGNOSTIC_SOCKS5,
    FP_DIAGNOSTIC_DNS,
    FP_DIAGNOSTIC_SOCKS_CONNECT,
    FP_DIAGNOSTIC_TRANSPARENT,
    FP_DIAGNOSTIC_DONE,
};

enum fp_diagnostic_state {
    FP_DIAGNOSTIC_PENDING,
    FP_DIAGNOSTIC_RUNNING,
    FP_DIAGNOSTIC_OK,
    FP_DIAGNOSTIC_FAIL,
    FP_DIAGNOSTIC_CANCELLED,
};

enum fp_diagnostic_reason {
    FP_DIAGNOSTIC_REASON_NONE,
    FP_DIAGNOSTIC_REASON_CANCELLED,
    FP_DIAGNOSTIC_REASON_CONFIG_MISSING,
    FP_DIAGNOSTIC_REASON_CONFIG_INVALID,
    FP_DIAGNOSTIC_REASON_DAEMON_STOPPED,
    FP_DIAGNOSTIC_REASON_DAEMON_CONFIG_MISMATCH,
    FP_DIAGNOSTIC_REASON_LISTENER_UNREACHABLE,
    FP_DIAGNOSTIC_REASON_FIREWALL_INCOMPLETE,
    FP_DIAGNOSTIC_REASON_PROXY_UNREACHABLE,
    FP_DIAGNOSTIC_REASON_SOCKS_IO,
    FP_DIAGNOSTIC_REASON_SOCKS_VERSION,
    FP_DIAGNOSTIC_REASON_SOCKS_AUTH,
    FP_DIAGNOSTIC_REASON_DNS_FAILED,
    FP_DIAGNOSTIC_REASON_SOCKS_CONNECT_REJECTED,
    FP_DIAGNOSTIC_REASON_TRANSPARENT_FAILED,
    FP_DIAGNOSTIC_REASON_INTERNAL,
};

struct fp_diagnostic_item {
    enum fp_diagnostic_step step;
    enum fp_diagnostic_state state;
    enum fp_diagnostic_reason reason;
    int error_code;
    int detail_code;
};

struct fp_diagnostic_report {
    struct fp_diagnostic_item items[FP_DIAGNOSTIC_STEP_COUNT];
    size_t completed;
    bool success;
    bool cancelled;
};

struct fp_diagnostic_event {
    struct fp_diagnostic_item item;
    size_t index;
    size_t total;
};

typedef void (*fp_diagnostic_callback)(const struct fp_diagnostic_event *event, void *context);

int fp_parse_proxy(const char *value, struct fp_config *config);
int fp_parse_bypass_list(const char *value, struct fp_config *config);
int fp_config_load(struct fp_config *config);
int fp_config_save(const struct fp_config *config);
bool fp_config_exists(void);
enum fp_ui_language fp_ui_language_load(void);
int fp_ui_language_save(enum fp_ui_language language);

int fp_firewall_enable(const struct fp_config *config);
int fp_firewall_disable(void);
int fp_firewall_is_enabled(const struct fp_config *config);

int fp_lock_acquire(void);
void fp_lock_release(int lock_fd);
int fp_start_daemon(const struct fp_config *config);
int fp_stop_daemon(void);
pid_t fp_read_pid(void);
int fp_write_pid(const struct fp_config *config);
void fp_remove_pid(void);
bool fp_daemon_matches_config(const struct fp_config *config);

int fp_proxy_run(const struct fp_config *config, int ready_fd);
int fp_socks5_drain_bind(int socket_fd);

struct fp_stats_conn_view {
    struct in_addr dest_addr;
    unsigned short dest_port;
    pid_t pid;
    uint64_t bytes_up;
    uint64_t bytes_down;
    uint64_t age_ms;
};

struct fp_stats_snapshot {
    bool available;
    uint64_t started_ms;
    uint64_t uptime_ms;
    uint64_t total_up;
    uint64_t total_down;
    size_t conn_count;
    struct fp_stats_conn_view connections[FP_MAX_CLIENTS];
};

int fp_stats_create(void);
int fp_stats_open_readonly(void);
void fp_stats_reopen_readonly(void);
void fp_stats_close(void);
void fp_stats_unlink(void);
int fp_stats_claim(const struct sockaddr_in *destination);
void fp_stats_add(int slot_index, uint64_t bytes_up, uint64_t bytes_down);
void fp_stats_release(int slot_index);
void fp_stats_clear_pid(pid_t pid);
int fp_stats_snapshot(struct fp_stats_snapshot *snapshot);

int fp_web_probe_init(void);
int fp_web_probe(const char *domain, unsigned short port, int *latency_ms,
                 atomic_bool *cancel_flag);

int fp_test_run(enum fp_test_mode mode, struct fp_test_report *report,
                fp_test_event_callback on_event, void *context,
                atomic_bool *cancel_flag);

int fp_diagnostic_run(struct fp_diagnostic_report *report, fp_diagnostic_callback on_event,
                      void *context, atomic_bool *cancel_flag);

int fp_autostart_enable(void);
int fp_autostart_disable(void);
int fp_autostart_is_enabled(void);
int fp_autostart_remove(void);

int fp_enable_proxy(const char *proxy);
int fp_enable_saved_proxy(void);
int fp_set_bypass(const char *bypass_list);
int fp_disable_proxy(void);
int fp_uninstall(void);
void fp_collect_status(struct fp_status *status);
int fp_tui_run(void);

void fp_format_bytes(char *buffer, size_t buffer_size, uint64_t bytes);
void fp_format_rate(char *buffer, size_t buffer_size, double bytes_per_sec);

#endif
