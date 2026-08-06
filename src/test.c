#include "free_proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

struct test_target {
    const char *name;
    const char *domain;
    unsigned short port;
};

struct speed_target {
    const char *name;
    const char *host;
    unsigned short port;
    const char *path;
};

static const struct test_target SITE_TARGETS[] = {
    {"GitHub", "github.com", 443},
    {"GitLab", "gitlab.com", 443},
    {"OpenAI API", "api.openai.com", 443},
    {"ChatGPT", "chatgpt.com", 443},
    {"Google", "www.google.com", 443},
    {"YouTube", "www.youtube.com", 443},
    {"Wikipedia", "en.wikipedia.org", 443},
    {"X", "x.com", 443},
    {"Reddit", "www.reddit.com", 443},
    {"Discord", "discord.com", 443},
    {"Telegram", "web.telegram.org", 443},
    {"Cloudflare", "www.cloudflare.com", 443},
    {"Microsoft", "www.microsoft.com", 443},
    {"Apple", "www.apple.com", 443},
    {"Amazon", "www.amazon.com", 443},
    {"Netflix", "www.netflix.com", 443},
    {"Spotify", "www.spotify.com", 443},
    {"Docker Hub", "hub.docker.com", 443},
    {"npm", "registry.npmjs.org", 443},
    {"PyPI", "pypi.org", 443},
    {"Hugging Face", "huggingface.co", 443},
    {"Stack Overflow", "stackoverflow.com", 443},
    {"Vercel", "vercel.com", 443},
    {"Ubuntu", "archive.ubuntu.com", 80},
    {"Ubuntu Security", "security.ubuntu.com", 80},
};

static const struct speed_target SPEED_TARGETS[] = {
    {"Tele2 10MB", "speedtest.tele2.net", 80, "/10MB.zip"},
    {"OVH 10MB", "proof.ovh.net", 80, "/files/10Mb.dat"},
    {"CacheFly 10MB", "cachefly.cachefly.net", 80, "/10mb.test"},
};

static int cancelled(volatile sig_atomic_t *cancel_flag) {
    return cancel_flag != NULL && *cancel_flag != 0;
}

static long long now_ms(void) {
    struct timeval value;

    if (gettimeofday(&value, NULL) != 0) {
        return -1;
    }
    return (long long)value.tv_sec * 1000LL + (long long)value.tv_usec / 1000LL;
}

static int set_socket_timeouts(int file_descriptor, int timeout_ms) {
    struct timeval timeout = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };

    return setsockopt(file_descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
                   setsockopt(file_descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0
               ? 0
               : -1;
}

static int connect_with_timeout(int file_descriptor, const struct sockaddr *address,
                                socklen_t address_length, int timeout_ms) {
    int original_flags = fcntl(file_descriptor, F_GETFL);
    struct pollfd descriptor = {.fd = file_descriptor, .events = POLLOUT};
    int socket_error = 0;
    socklen_t socket_error_length = sizeof(socket_error);
    int result;

    if (original_flags < 0 || fcntl(file_descriptor, F_SETFL, original_flags | O_NONBLOCK) != 0) {
        return -1;
    }
    result = connect(file_descriptor, address, address_length);
    if (result != 0 && errno == EINPROGRESS) {
        result = poll(&descriptor, 1, timeout_ms);
        if (result > 0 &&
            getsockopt(file_descriptor, SOL_SOCKET, SO_ERROR, &socket_error,
                       &socket_error_length) == 0 &&
            socket_error == 0) {
            result = 0;
        } else {
            result = -1;
        }
    }
    if (fcntl(file_descriptor, F_SETFL, original_flags) != 0) {
        return -1;
    }
    return result;
}

static int write_all(int file_descriptor, const void *buffer, size_t length) {
    const unsigned char *cursor = buffer;

    while (length > 0) {
        ssize_t written = send(file_descriptor, cursor, length, MSG_NOSIGNAL);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return -1;
        }
        cursor += written;
        length -= (size_t)written;
    }
    return 0;
}

static int read_all(int file_descriptor, void *buffer, size_t length) {
    unsigned char *cursor = buffer;

    while (length > 0) {
        ssize_t received = recv(file_descriptor, cursor, length, 0);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return -1;
        }
        cursor += received;
        length -= (size_t)received;
    }
    return 0;
}

static int open_socks(const struct fp_config *config, int connect_timeout_ms, int io_timeout_ms) {
    int socket_fd;
    unsigned char greeting[] = {0x05, 0x01, 0x00};
    unsigned char response[2];
    struct sockaddr_in proxy = {
        .sin_family = AF_INET,
        .sin_addr = config->proxy_addr,
        .sin_port = htons(config->proxy_port),
    };

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0 ||
        connect_with_timeout(socket_fd, (struct sockaddr *)&proxy, sizeof(proxy),
                             connect_timeout_ms) != 0 ||
        set_socket_timeouts(socket_fd, io_timeout_ms) != 0 ||
        write_all(socket_fd, greeting, sizeof(greeting)) != 0 ||
        read_all(socket_fd, response, sizeof(response)) != 0 || response[0] != 0x05 ||
        response[1] != 0x00) {
        if (socket_fd >= 0) {
            close(socket_fd);
        }
        return -1;
    }
    return socket_fd;
}

static int connect_socks_domain(const struct fp_config *config, const char *domain,
                                unsigned short port, int connect_timeout_ms, int io_timeout_ms) {
    unsigned char request_header[] = {0x05, 0x01, 0x00, 0x03};
    unsigned char domain_length;
    unsigned char port_bytes[2];
    unsigned char response[2];
    size_t length = strlen(domain);
    int socket_fd;

    if (length == 0 || length > 255) {
        return -1;
    }
    socket_fd = open_socks(config, connect_timeout_ms, io_timeout_ms);
    if (socket_fd < 0) {
        return -1;
    }
    domain_length = (unsigned char)length;
    port_bytes[0] = (unsigned char)(port >> 8);
    port_bytes[1] = (unsigned char)(port & 0xff);
    if (write_all(socket_fd, request_header, sizeof(request_header)) != 0 ||
        write_all(socket_fd, &domain_length, 1) != 0 ||
        write_all(socket_fd, domain, length) != 0 ||
        write_all(socket_fd, port_bytes, sizeof(port_bytes)) != 0 ||
        read_all(socket_fd, response, sizeof(response)) != 0 || response[0] != 0x05 ||
        response[1] != 0x00 || fp_socks5_drain_bind(socket_fd) != 0) {
        close(socket_fd);
        return -1;
    }
    return socket_fd;
}

static void append_failed(struct fp_test_report *report, const char *name) {
    size_t used = strlen(report->failures);

    if (used < sizeof(report->failures)) {
        (void)snprintf(report->failures + used, sizeof(report->failures) - used, "%s%s",
                       used == 0 ? "" : ", ", name);
    }
}

static void emit_event(fp_test_event_callback on_event, void *context,
                       const struct fp_test_progress_event *event) {
    if (on_event != NULL) {
        on_event(event, context);
    }
}

static void fill_site(struct fp_test_site_result *site, const char *name, const char *domain) {
    memset(site, 0, sizeof(*site));
    site->state = FP_TEST_SITE_PENDING;
    site->latency_ms = -1;
    (void)snprintf(site->name, sizeof(site->name), "%s", name);
    (void)snprintf(site->domain, sizeof(site->domain), "%s", domain);
}

static int listener_ready(void) {
    struct sockaddr_in listener = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(FP_LISTEN_PORT),
    };
    int listener_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (listener_fd < 0 ||
        connect_with_timeout(listener_fd, (struct sockaddr *)&listener, sizeof(listener),
                             FP_TEST_TIMEOUT_MS) != 0) {
        if (listener_fd >= 0) {
            close(listener_fd);
        }
        return -1;
    }
    close(listener_fd);
    return 0;
}

static int measure_latency(const struct fp_config *config, const char *domain, unsigned short port,
                           int *latency_ms, volatile sig_atomic_t *cancel_flag) {
    long long start;
    long long end;
    int socket_fd;

    if (cancelled(cancel_flag)) {
        return -2;
    }
    start = now_ms();
    if (start < 0) {
        return -1;
    }
    socket_fd = connect_socks_domain(config, domain, port, FP_TEST_TIMEOUT_MS, FP_TEST_TIMEOUT_MS);
    end = now_ms();
    if (socket_fd < 0 || end < 0) {
        return cancelled(cancel_flag) ? -2 : -1;
    }
    close(socket_fd);
    *latency_ms = (int)(end - start);
    if (*latency_ms < 0) {
        *latency_ms = 0;
    }
    return 0;
}

static int skip_http_headers(int socket_fd, unsigned char *buffer, size_t capacity,
                             size_t *body_offset, size_t *buffered, volatile sig_atomic_t *cancel_flag) {
    size_t used = 0;

    while (used + 1 < capacity) {
        ssize_t received;
        size_t index;

        if (cancelled(cancel_flag)) {
            return -2;
        }
        received = recv(socket_fd, buffer + used, capacity - used, 0);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return -1;
        }
        used += (size_t)received;
        for (index = 0; index + 3 < used; ++index) {
            if (buffer[index] == '\r' && buffer[index + 1] == '\n' && buffer[index + 2] == '\r' &&
                buffer[index + 3] == '\n') {
                *body_offset = index + 4;
                *buffered = used;
                return 0;
            }
        }
    }
    return -1;
}

static int measure_speed(const struct fp_config *config, const struct speed_target *target,
                         size_t index, size_t total, size_t *bytes_downloaded, double *speed_mbps,
                         fp_test_event_callback on_event, void *context,
                         volatile sig_atomic_t *cancel_flag) {
    char request[256];
    unsigned char buffer[16384];
    struct fp_test_progress_event event;
    size_t body_offset = 0;
    size_t buffered = 0;
    size_t downloaded = 0;
    long long start;
    long long end;
    long long deadline;
    long long last_emit = 0;
    int socket_fd;
    int written;

    *bytes_downloaded = 0;
    *speed_mbps = 0.0;
    if (cancelled(cancel_flag)) {
        return -2;
    }
    socket_fd = connect_socks_domain(config, target->host, target->port, FP_TEST_SPEED_CONNECT_MS,
                                     FP_TEST_SPEED_STALL_MS);
    if (socket_fd < 0) {
        return cancelled(cancel_flag) ? -2 : -1;
    }
    written = snprintf(request, sizeof(request),
                       "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: free_proxy\r\n\r\n",
                       target->path, target->host);
    if (written < 0 || (size_t)written >= sizeof(request) ||
        write_all(socket_fd, request, (size_t)written) != 0) {
        close(socket_fd);
        return -1;
    }
    if (skip_http_headers(socket_fd, buffer, sizeof(buffer), &body_offset, &buffered, cancel_flag) !=
        0) {
        close(socket_fd);
        return cancelled(cancel_flag) ? -2 : -1;
    }
    if (body_offset > buffered) {
        close(socket_fd);
        return -1;
    }
    downloaded = buffered - body_offset;
    if (downloaded > FP_TEST_SPEED_MAX_BYTES) {
        downloaded = FP_TEST_SPEED_MAX_BYTES;
    }
    start = now_ms();
    if (start < 0) {
        close(socket_fd);
        return -1;
    }
    deadline = start + FP_TEST_SPEED_TOTAL_MS;
    last_emit = start;
    memset(&event, 0, sizeof(event));
    event.phase = FP_TEST_PHASE_SPEED;
    event.index = index;
    event.total = total;
    event.state = FP_TEST_SITE_RUNNING;
    (void)snprintf(event.name, sizeof(event.name), "%s", target->name);
    (void)snprintf(event.domain, sizeof(event.domain), "%s", target->host);
    while (downloaded < FP_TEST_SPEED_MAX_BYTES) {
        ssize_t received;
        long long now = now_ms();
        size_t want;

        if (cancelled(cancel_flag)) {
            close(socket_fd);
            return -2;
        }
        if (now < 0 || now > deadline) {
            break;
        }
        want = FP_TEST_SPEED_MAX_BYTES - downloaded;
        if (want > sizeof(buffer)) {
            want = sizeof(buffer);
        }
        received = recv(socket_fd, buffer, want, 0);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            break;
        }
        downloaded += (size_t)received;
        now = now_ms();
        if (now > 0 && (now - last_emit >= 200 || downloaded >= FP_TEST_SPEED_MAX_BYTES)) {
            double live = 0.0;

            if (now > start) {
                live = ((double)downloaded * 8.0) / ((double)(now - start) * 1000.0);
            }
            event.bytes_downloaded = downloaded;
            event.speed_mbps = live;
            emit_event(on_event, context, &event);
            last_emit = now;
        }
    }
    end = now_ms();
    close(socket_fd);
    *bytes_downloaded = downloaded;
    if (end <= start || downloaded == 0) {
        return -1;
    }
    *speed_mbps = ((double)downloaded * 8.0) / ((double)(end - start) * 1000.0);
    return downloaded > 0 ? 0 : -1;
}

static int run_site_tests(enum fp_test_mode mode, struct fp_config *config,
                          struct fp_test_report *report, fp_test_event_callback on_event,
                          void *context, volatile sig_atomic_t *cancel_flag) {
    enum fp_test_phase phase =
        mode == FP_TEST_MODE_LATENCY ? FP_TEST_PHASE_LATENCY : FP_TEST_PHASE_CONNECTIVITY;
    size_t index;

    for (index = 0; index < report->site_count; ++index) {
        struct fp_test_progress_event event;
        int latency_ms = -1;
        int result;

        if (cancelled(cancel_flag)) {
            report->cancelled = true;
            report->sites[index].state = FP_TEST_SITE_CANCELLED;
            return -1;
        }
        report->sites[index].state = FP_TEST_SITE_RUNNING;
        memset(&event, 0, sizeof(event));
        event.phase = phase;
        event.index = index + 1;
        event.total = report->site_count;
        event.state = FP_TEST_SITE_RUNNING;
        (void)snprintf(event.name, sizeof(event.name), "%s", report->sites[index].name);
        (void)snprintf(event.domain, sizeof(event.domain), "%s", report->sites[index].domain);
        emit_event(on_event, context, &event);

        result = measure_latency(config, SITE_TARGETS[index].domain, SITE_TARGETS[index].port,
                                 &latency_ms, cancel_flag);
        if (result == -2 || cancelled(cancel_flag)) {
            report->cancelled = true;
            report->sites[index].state = FP_TEST_SITE_CANCELLED;
            return -1;
        }
        if (result == 0) {
            report->sites[index].state = FP_TEST_SITE_OK;
            ++report->sites_passed;
            event.state = FP_TEST_SITE_OK;
            if (mode == FP_TEST_MODE_LATENCY) {
                report->sites[index].latency_ms = latency_ms;
                event.latency_ms = latency_ms;
            } else {
                report->sites[index].latency_ms = -1;
                event.latency_ms = -1;
            }
        } else {
            report->sites[index].state = FP_TEST_SITE_FAIL;
            append_failed(report, report->sites[index].domain);
            event.state = FP_TEST_SITE_FAIL;
            event.latency_ms = -1;
        }
        emit_event(on_event, context, &event);
    }
    return 0;
}

static int run_speed_tests(struct fp_config *config, struct fp_test_report *report,
                           fp_test_event_callback on_event, void *context,
                           volatile sig_atomic_t *cancel_flag) {
    size_t index;

    for (index = 0; index < report->speed_count; ++index) {
        struct fp_test_progress_event event;
        size_t bytes = 0;
        double mbps = 0.0;
        int result;

        if (cancelled(cancel_flag)) {
            report->cancelled = true;
            report->speed[index].state = FP_TEST_SITE_CANCELLED;
            return -1;
        }
        report->speed[index].state = FP_TEST_SITE_RUNNING;
        memset(&event, 0, sizeof(event));
        event.phase = FP_TEST_PHASE_SPEED;
        event.index = index + 1;
        event.total = report->speed_count;
        event.state = FP_TEST_SITE_RUNNING;
        (void)snprintf(event.name, sizeof(event.name), "%s", report->speed[index].name);
        (void)snprintf(event.domain, sizeof(event.domain), "%s", report->speed[index].domain);
        emit_event(on_event, context, &event);

        result = measure_speed(config, &SPEED_TARGETS[index], index + 1, report->speed_count, &bytes,
                               &mbps, on_event, context, cancel_flag);
        if (result == -2 || cancelled(cancel_flag)) {
            report->cancelled = true;
            report->speed[index].state = FP_TEST_SITE_CANCELLED;
            report->speed[index].bytes_downloaded = bytes;
            report->speed[index].speed_mbps = mbps;
            return -1;
        }
        report->speed[index].bytes_downloaded = bytes;
        report->speed[index].speed_mbps = mbps;
        if (result == 0) {
            report->speed[index].state = FP_TEST_SITE_OK;
            ++report->speed_passed;
            if (mbps > report->best_speed_mbps) {
                report->best_speed_mbps = mbps;
            }
            event.state = FP_TEST_SITE_OK;
        } else {
            report->speed[index].state = FP_TEST_SITE_FAIL;
            append_failed(report, report->speed[index].domain);
            event.state = FP_TEST_SITE_FAIL;
        }
        event.bytes_downloaded = bytes;
        event.speed_mbps = mbps;
        emit_event(on_event, context, &event);
    }
    return 0;
}

int fp_test_run(enum fp_test_mode mode, struct fp_test_report *report,
                fp_test_event_callback on_event, void *context,
                volatile sig_atomic_t *cancel_flag) {
    struct fp_config config;
    struct fp_test_progress_event event;
    size_t index;
    int ok = 0;

    if (report == NULL) {
        return -1;
    }
    memset(report, 0, sizeof(*report));
    report->mode = mode;
    report->site_count = sizeof(SITE_TARGETS) / sizeof(SITE_TARGETS[0]);
    report->speed_count = sizeof(SPEED_TARGETS) / sizeof(SPEED_TARGETS[0]);
    if (report->site_count > FP_TEST_MAX_SITES || report->speed_count > FP_TEST_MAX_SPEED) {
        return -1;
    }
    for (index = 0; index < report->site_count; ++index) {
        fill_site(&report->sites[index], SITE_TARGETS[index].name, SITE_TARGETS[index].domain);
    }
    for (index = 0; index < report->speed_count; ++index) {
        fill_site(&report->speed[index], SPEED_TARGETS[index].name, SPEED_TARGETS[index].host);
    }

    memset(&event, 0, sizeof(event));
    event.phase = FP_TEST_PHASE_PREFLIGHT;
    event.total = 1;
    event.index = 1;
    (void)snprintf(event.name, sizeof(event.name), "%s", "preflight");
    emit_event(on_event, context, &event);

    if (fp_config_load(&config) != 0 || !fp_firewall_is_enabled(&config) || listener_ready() != 0) {
        report->listener_ok = false;
        event.phase = FP_TEST_PHASE_DONE;
        event.state = FP_TEST_SITE_FAIL;
        emit_event(on_event, context, &event);
        return -1;
    }
    report->listener_ok = true;

    if (mode == FP_TEST_MODE_SPEED) {
        (void)run_speed_tests(&config, report, on_event, context, cancel_flag);
        ok = !report->cancelled && report->speed_passed == report->speed_count;
    } else {
        (void)run_site_tests(mode, &config, report, on_event, context, cancel_flag);
        ok = !report->cancelled && report->sites_passed == report->site_count;
    }

    memset(&event, 0, sizeof(event));
    event.phase = FP_TEST_PHASE_DONE;
    event.state = report->cancelled ? FP_TEST_SITE_CANCELLED :
                                     (ok ? FP_TEST_SITE_OK : FP_TEST_SITE_FAIL);
    emit_event(on_event, context, &event);
    return ok ? 0 : -1;
}
