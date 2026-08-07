#include "free_proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
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

struct resolver_job {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    struct addrinfo hints;
    struct addrinfo *result;
    char host[256];
    char service[8];
    int status;
    int done;
    int abandoned;
};

static int cancelled(atomic_bool *cancel_flag) {
    return cancel_flag != NULL && atomic_load_explicit(cancel_flag, memory_order_acquire);
}

static void destroy_resolver_job(struct resolver_job *job) {
    (void)pthread_cond_destroy(&job->condition);
    (void)pthread_mutex_destroy(&job->mutex);
    free(job);
}

static void *resolver_main(void *context) {
    struct resolver_job *job = context;
    struct addrinfo *result = NULL;
    int status = getaddrinfo(job->host, job->service, &job->hints, &result);

    (void)pthread_mutex_lock(&job->mutex);
    if (job->abandoned) {
        (void)pthread_mutex_unlock(&job->mutex);
        if (result != NULL) {
            freeaddrinfo(result);
        }
        destroy_resolver_job(job);
        return NULL;
    }
    job->result = result;
    job->status = status;
    job->done = 1;
    (void)pthread_cond_signal(&job->condition);
    (void)pthread_mutex_unlock(&job->mutex);
    return NULL;
}

static int resolve_ipv4(const char *host, const char *service, struct addrinfo **result,
                        atomic_bool *cancel_flag, int *resolver_error) {
    struct resolver_job *job;
    pthread_t resolver;
    int wait_error = 0;
    int status;

    if (resolver_error != NULL) {
        *resolver_error = 0;
    }
    if (cancelled(cancel_flag)) {
        return -2;
    }
    job = calloc(1, sizeof(*job));
    if (job == NULL) {
        return -1;
    }
    if (strlen(host) >= sizeof(job->host) || strlen(service) >= sizeof(job->service)) {
        free(job);
        return -1;
    }
    (void)snprintf(job->host, sizeof(job->host), "%s", host);
    (void)snprintf(job->service, sizeof(job->service), "%s", service);
    if (pthread_mutex_init(&job->mutex, NULL) != 0) {
        free(job);
        return -1;
    }
    if (pthread_cond_init(&job->condition, NULL) != 0) {
        (void)pthread_mutex_destroy(&job->mutex);
        free(job);
        return -1;
    }
    job->hints.ai_family = AF_INET;
    job->hints.ai_socktype = SOCK_STREAM;
    if (pthread_create(&resolver, NULL, resolver_main, job) != 0) {
        destroy_resolver_job(job);
        return -1;
    }

    (void)pthread_mutex_lock(&job->mutex);
    while (!job->done && !cancelled(cancel_flag) && wait_error == 0) {
        struct timespec deadline;

        if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
            wait_error = -1;
            break;
        }
        deadline.tv_nsec += 100000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            ++deadline.tv_sec;
            deadline.tv_nsec -= 1000000000L;
        }
        status = pthread_cond_timedwait(&job->condition, &job->mutex, &deadline);
        if (status != 0 && status != ETIMEDOUT) {
            wait_error = -1;
        }
    }
    if (!job->done) {
        job->abandoned = 1;
        (void)pthread_mutex_unlock(&job->mutex);
        (void)pthread_detach(resolver);
        return cancelled(cancel_flag) ? -2 : -1;
    }
    status = job->status;
    *result = job->result;
    if (resolver_error != NULL) {
        *resolver_error = status;
    }
    (void)pthread_mutex_unlock(&job->mutex);
    (void)pthread_join(resolver, NULL);
    destroy_resolver_job(job);
    if (cancelled(cancel_flag)) {
        if (*result != NULL) {
            freeaddrinfo(*result);
            *result = NULL;
        }
        return -2;
    }
    if (status != 0 && *result != NULL) {
        freeaddrinfo(*result);
        *result = NULL;
    }
    return status == 0 && *result != NULL ? 0 : -1;
}

static long long now_ms(void) {
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        return -1;
    }
    return (long long)value.tv_sec * 1000LL + (long long)value.tv_nsec / 1000000LL;
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
        if (result == 0) {
            errno = ETIMEDOUT;
            result = -1;
        } else if (result > 0) {
            if (getsockopt(file_descriptor, SOL_SOCKET, SO_ERROR, &socket_error,
                           &socket_error_length) == 0) {
                if (socket_error == 0) {
                    result = 0;
                } else {
                    errno = socket_error;
                    result = -1;
                }
            } else {
                result = -1;
            }
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

/*
 * Connect to an IPv4 target through the transparent forwarder path (iptables REDIRECT).
 * This exercises free_proxy itself and produces monitor traffic, unlike talking to SOCKS5
 * directly (which is excluded from REDIRECT).
 */
static int connect_through_forwarder(const char *host, unsigned short port, int connect_timeout_ms,
                                     int io_timeout_ms, atomic_bool *cancel_flag) {
    struct addrinfo *result = NULL;
    struct addrinfo *entry;
    char port_text[8];
    int socket_fd = -1;
    int status;

    if (snprintf(port_text, sizeof(port_text), "%u", port) < 0) {
        return -1;
    }
    status = resolve_ipv4(host, port_text, &result, cancel_flag, NULL);
    if (status != 0 || result == NULL) {
        return -1;
    }
    for (entry = result; entry != NULL; entry = entry->ai_next) {
        socket_fd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (socket_fd < 0) {
            continue;
        }
        if (cancelled(cancel_flag)) {
            close(socket_fd);
            socket_fd = -1;
            break;
        }
        if (connect_with_timeout(socket_fd, entry->ai_addr, entry->ai_addrlen, connect_timeout_ms) ==
                0 &&
            set_socket_timeouts(socket_fd, io_timeout_ms) == 0) {
            break;
        }
        close(socket_fd);
        socket_fd = -1;
    }
    freeaddrinfo(result);
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

static enum fp_diagnostic_reason diagnostic_socks_connect(
    const struct fp_config *config, const struct sockaddr_in *destination,
    int *error_code, int *detail_code, atomic_bool *cancel_flag);

static int measure_socks_connect_once(const struct fp_config *config,
                                      const struct sockaddr_in *destination,
                                      int *latency_ms, atomic_bool *cancel_flag) {
    enum fp_diagnostic_reason reason;
    long long start;
    long long end;
    int error_code = 0;
    int detail_code = 0;

    if (cancelled(cancel_flag)) {
        return -2;
    }
    start = now_ms();
    if (start < 0) {
        return -1;
    }
    reason = diagnostic_socks_connect(config, destination, &error_code, &detail_code,
                                      cancel_flag);
    end = now_ms();
    if (reason != FP_DIAGNOSTIC_REASON_NONE || end < 0) {
        return cancelled(cancel_flag) ? -2 : -1;
    }
    *latency_ms = (int)(end - start);
    if (*latency_ms < 0) {
        *latency_ms = 0;
    }
    return 0;
}

static int measure_latency(const struct fp_config *config, const char *domain, unsigned short port,
                           size_t sample_total, int *latency_ms,
                           atomic_bool *cancel_flag) {
    enum { FP_LATENCY_SAMPLE_COUNT = 3 };
    struct sockaddr_in destination;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    int samples[FP_LATENCY_SAMPLE_COUNT];
    char port_text[8];
    size_t sample;
    int result = -1;

    if ((sample_total != 1 && sample_total != FP_LATENCY_SAMPLE_COUNT) ||
        snprintf(port_text, sizeof(port_text), "%u", port) < 0) {
        return -1;
    }
    result = resolve_ipv4(domain, port_text, &addresses, cancel_flag, NULL);
    if (result != 0 || addresses == NULL) {
        return cancelled(cancel_flag) ? -2 : -1;
    }

    result = -1;
    for (address = addresses; address != NULL; address = address->ai_next) {
        if (address->ai_addrlen < sizeof(destination)) {
            continue;
        }
        memcpy(&destination, address->ai_addr, sizeof(destination));
        result = measure_socks_connect_once(config, &destination, &samples[0], cancel_flag);
        if (result == 0 || result == -2) {
            break;
        }
    }
    freeaddrinfo(addresses);
    if (result != 0) {
        return result;
    }

    for (sample = 1; sample < sample_total; ++sample) {
        result = measure_socks_connect_once(config, &destination, &samples[sample], cancel_flag);
        if (result != 0) {
            return result;
        }
    }
    if (sample_total == FP_LATENCY_SAMPLE_COUNT) {
        int temporary;

        if (samples[0] > samples[1]) {
            temporary = samples[0];
            samples[0] = samples[1];
            samples[1] = temporary;
        }
        if (samples[1] > samples[2]) {
            temporary = samples[1];
            samples[1] = samples[2];
            samples[2] = temporary;
        }
        if (samples[0] > samples[1]) {
            temporary = samples[0];
            samples[0] = samples[1];
            samples[1] = temporary;
        }
        *latency_ms = samples[1];
    } else {
        *latency_ms = samples[0];
    }
    return 0;
}

static int http_response_success(const unsigned char *buffer, size_t header_length) {
    size_t index;
    int status;

    if (header_length < 12 || memcmp(buffer, "HTTP/", 5) != 0) {
        return 0;
    }
    for (index = 5; index < header_length && buffer[index] != ' ' && buffer[index] != '\r';
         ++index) {
    }
    if (index + 3 >= header_length || buffer[index] != ' ' || buffer[index + 1] < '0' ||
        buffer[index + 1] > '9' || buffer[index + 2] < '0' || buffer[index + 2] > '9' ||
        buffer[index + 3] < '0' || buffer[index + 3] > '9') {
        return 0;
    }
    status = (buffer[index + 1] - '0') * 100 + (buffer[index + 2] - '0') * 10 +
             (buffer[index + 3] - '0');
    return status >= 200 && status < 300;
}

static int skip_http_headers(int socket_fd, unsigned char *buffer, size_t capacity,
                             size_t *body_offset, size_t *buffered, atomic_bool *cancel_flag) {
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
                if (!http_response_success(buffer, index + 4)) {
                    return -1;
                }
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
                         atomic_bool *cancel_flag) {
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
    (void)config;
    if (cancelled(cancel_flag)) {
        return -2;
    }
    socket_fd = connect_through_forwarder(target->host, target->port, FP_TEST_SPEED_CONNECT_MS,
                                          FP_TEST_SPEED_STALL_MS, cancel_flag);
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
    start = now_ms();
    if (start < 0) {
        close(socket_fd);
        return -1;
    }
    deadline = start + FP_TEST_SPEED_TOTAL_MS;
    last_emit = start;
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
                          void *context, atomic_bool *cancel_flag) {
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

        /* Connectivity needs one real CONNECT; latency uses the median of three CONNECTs. */
        result = measure_latency(config, SITE_TARGETS[index].domain, SITE_TARGETS[index].port,
                                 mode == FP_TEST_MODE_LATENCY ? 3U : 1U,
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
                           atomic_bool *cancel_flag) {
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

static void diagnostic_emit(struct fp_diagnostic_report *report, size_t index,
                            enum fp_diagnostic_state state,
                            enum fp_diagnostic_reason reason, int error_code, int detail_code,
                            fp_diagnostic_callback on_event, void *context) {
    struct fp_diagnostic_item *item = &report->items[index];
    struct fp_diagnostic_event event;

    item->step = (enum fp_diagnostic_step)index;
    item->state = state;
    item->reason = reason;
    item->error_code = error_code;
    item->detail_code = detail_code;
    if (state == FP_DIAGNOSTIC_OK || state == FP_DIAGNOSTIC_FAIL ||
        state == FP_DIAGNOSTIC_CANCELLED) {
        report->completed = index + 1;
    }
    if (on_event != NULL) {
        memset(&event, 0, sizeof(event));
        event.item = *item;
        event.index = index + 1;
        event.total = FP_DIAGNOSTIC_STEP_COUNT;
        on_event(&event, context);
    }
}

static void diagnostic_done(struct fp_diagnostic_report *report,
                            fp_diagnostic_callback on_event, void *context) {
    struct fp_diagnostic_event event;

    if (on_event == NULL) {
        return;
    }
    memset(&event, 0, sizeof(event));
    event.item.step = FP_DIAGNOSTIC_DONE;
    event.item.state = report->cancelled ? FP_DIAGNOSTIC_CANCELLED :
                       report->success   ? FP_DIAGNOSTIC_OK :
                                           FP_DIAGNOSTIC_FAIL;
    event.item.reason = report->cancelled ? FP_DIAGNOSTIC_REASON_CANCELLED :
                                            FP_DIAGNOSTIC_REASON_NONE;
    event.index = report->completed;
    event.total = FP_DIAGNOSTIC_STEP_COUNT;
    on_event(&event, context);
}

static int diagnostic_cancel(struct fp_diagnostic_report *report, size_t index,
                             fp_diagnostic_callback on_event, void *context,
                             atomic_bool *cancel_flag) {
    if (!cancelled(cancel_flag)) {
        return 0;
    }
    report->cancelled = true;
    diagnostic_emit(report, index, FP_DIAGNOSTIC_CANCELLED,
                    FP_DIAGNOSTIC_REASON_CANCELLED, 0, 0, on_event, context);
    diagnostic_done(report, on_event, context);
    return 1;
}

static int diagnostic_fail(struct fp_diagnostic_report *report, size_t index,
                           enum fp_diagnostic_reason reason, int error_code, int detail_code,
                           fp_diagnostic_callback on_event, void *context) {
    diagnostic_emit(report, index, FP_DIAGNOSTIC_FAIL, reason, error_code, detail_code,
                    on_event, context);
    diagnostic_done(report, on_event, context);
    return -1;
}

static int read_all_diagnostic(int socket_fd, void *buffer, size_t length) {
    unsigned char *cursor = buffer;

    while (length > 0) {
        ssize_t received = recv(socket_fd, cursor, length, 0);

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            if (received == 0) {
                errno = ECONNRESET;
            }
            return -1;
        }
        cursor += received;
        length -= (size_t)received;
    }
    return 0;
}

static int diagnostic_proxy_tcp(const struct fp_config *config, int *error_code) {
    struct sockaddr_in proxy = {
        .sin_family = AF_INET,
        .sin_addr = config->proxy_addr,
        .sin_port = htons(config->proxy_port),
    };
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_fd < 0 ||
        connect_with_timeout(socket_fd, (struct sockaddr *)&proxy, sizeof(proxy),
                             FP_TEST_TIMEOUT_MS) != 0 ||
        set_socket_timeouts(socket_fd, FP_TEST_TIMEOUT_MS) != 0) {
        *error_code = errno;
        if (socket_fd >= 0) {
            close(socket_fd);
        }
        return -1;
    }
    return socket_fd;
}

static enum fp_diagnostic_reason diagnostic_socks_handshake(int socket_fd, int *error_code,
                                                            int *detail_code) {
    const unsigned char greeting[] = {0x05, 0x01, 0x00};
    unsigned char response[2];

    if (write_all(socket_fd, greeting, sizeof(greeting)) != 0 ||
        read_all_diagnostic(socket_fd, response, sizeof(response)) != 0) {
        *error_code = errno;
        return FP_DIAGNOSTIC_REASON_SOCKS_IO;
    }
    if (response[0] != 0x05) {
        *detail_code = response[0];
        return FP_DIAGNOSTIC_REASON_SOCKS_VERSION;
    }
    if (response[1] != 0x00) {
        *detail_code = response[1];
        return FP_DIAGNOSTIC_REASON_SOCKS_AUTH;
    }
    return FP_DIAGNOSTIC_REASON_NONE;
}

static enum fp_diagnostic_reason diagnostic_socks_connect(
    const struct fp_config *config, const struct sockaddr_in *destination,
    int *error_code, int *detail_code, atomic_bool *cancel_flag) {
    unsigned char request[10] = {0x05, 0x01, 0x00, 0x01};
    unsigned char response[2];
    enum fp_diagnostic_reason reason;
    int socket_fd = diagnostic_proxy_tcp(config, error_code);

    if (socket_fd < 0) {
        return FP_DIAGNOSTIC_REASON_PROXY_UNREACHABLE;
    }
    reason = diagnostic_socks_handshake(socket_fd, error_code, detail_code);
    if (reason != FP_DIAGNOSTIC_REASON_NONE) {
        close(socket_fd);
        return reason;
    }
    if (cancelled(cancel_flag)) {
        close(socket_fd);
        return FP_DIAGNOSTIC_REASON_CANCELLED;
    }
    memcpy(request + 4, &destination->sin_addr, 4);
    memcpy(request + 8, &destination->sin_port, 2);
    if (write_all(socket_fd, request, sizeof(request)) != 0 ||
        read_all_diagnostic(socket_fd, response, sizeof(response)) != 0) {
        *error_code = errno;
        close(socket_fd);
        return FP_DIAGNOSTIC_REASON_SOCKS_IO;
    }
    if (response[0] != 0x05) {
        *detail_code = response[0];
        close(socket_fd);
        return FP_DIAGNOSTIC_REASON_SOCKS_VERSION;
    }
    if (response[1] != 0x00) {
        *detail_code = response[1];
        close(socket_fd);
        return FP_DIAGNOSTIC_REASON_SOCKS_CONNECT_REJECTED;
    }
    if (fp_socks5_drain_bind(socket_fd) != 0) {
        *error_code = errno;
        close(socket_fd);
        return FP_DIAGNOSTIC_REASON_SOCKS_IO;
    }
    close(socket_fd);
    return FP_DIAGNOSTIC_REASON_NONE;
}

static int diagnostic_transparent_http(const struct sockaddr_in *destination,
                                       atomic_bool *cancel_flag, int *error_code) {
    static const char request[] =
        "GET / HTTP/1.0\r\nHost: github.com\r\nConnection: close\r\n\r\n";
    unsigned char response[5];
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_fd < 0 ||
        connect_with_timeout(socket_fd, (const struct sockaddr *)destination,
                             sizeof(*destination), FP_TEST_TIMEOUT_MS) != 0 ||
        set_socket_timeouts(socket_fd, FP_TEST_TIMEOUT_MS) != 0) {
        *error_code = errno;
        if (socket_fd >= 0) {
            close(socket_fd);
        }
        return -1;
    }
    if (cancelled(cancel_flag)) {
        close(socket_fd);
        return -2;
    }
    if (write_all(socket_fd, request, sizeof(request) - 1) != 0 ||
        read_all_diagnostic(socket_fd, response, sizeof(response)) != 0) {
        *error_code = errno;
        close(socket_fd);
        return -1;
    }
    close(socket_fd);
    if (memcmp(response, "HTTP/", sizeof(response)) != 0) {
        *error_code = EPROTO;
        return -1;
    }
    return 0;
}

int fp_diagnostic_run(struct fp_diagnostic_report *report, fp_diagnostic_callback on_event,
                      void *context, atomic_bool *cancel_flag) {
    static const char diagnostic_host[] = "github.com";
    static const char diagnostic_service[] = "80";
    struct fp_config config;
    struct sockaddr_in listener = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(FP_LISTEN_PORT),
    };
    struct sockaddr_in destination;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    enum fp_diagnostic_reason reason;
    int resolver_error = 0;
    int error_code = 0;
    int detail_code = 0;
    int socket_fd;
    size_t index;

    if (report == NULL) {
        return -1;
    }
    memset(report, 0, sizeof(*report));
    for (index = 0; index < FP_DIAGNOSTIC_STEP_COUNT; ++index) {
        report->items[index].step = (enum fp_diagnostic_step)index;
        report->items[index].state = FP_DIAGNOSTIC_PENDING;
    }

    index = FP_DIAGNOSTIC_CONFIG;
    diagnostic_emit(report, index, FP_DIAGNOSTIC_RUNNING, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);
    if (!fp_config_exists()) {
        return diagnostic_fail(report, index, FP_DIAGNOSTIC_REASON_CONFIG_MISSING,
                               ENOENT, 0, on_event, context);
    }
    if (fp_config_load(&config) != 0) {
        return diagnostic_fail(report, index, FP_DIAGNOSTIC_REASON_CONFIG_INVALID,
                               EINVAL, 0, on_event, context);
    }
    diagnostic_emit(report, index, FP_DIAGNOSTIC_OK, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);

    index = FP_DIAGNOSTIC_DAEMON;
    if (diagnostic_cancel(report, index, on_event, context, cancel_flag)) {
        return -1;
    }
    diagnostic_emit(report, index, FP_DIAGNOSTIC_RUNNING, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);
    if (!fp_daemon_matches_config(&config)) {
        enum fp_diagnostic_reason daemon_reason = fp_read_pid() > 1 ?
            FP_DIAGNOSTIC_REASON_DAEMON_CONFIG_MISMATCH :
            FP_DIAGNOSTIC_REASON_DAEMON_STOPPED;
        return diagnostic_fail(report, index, daemon_reason, ESRCH, 0, on_event, context);
    }
    diagnostic_emit(report, index, FP_DIAGNOSTIC_OK, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);

    index = FP_DIAGNOSTIC_LISTENER;
    diagnostic_emit(report, index, FP_DIAGNOSTIC_RUNNING, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0 ||
        connect_with_timeout(socket_fd, (struct sockaddr *)&listener, sizeof(listener),
                             FP_TEST_TIMEOUT_MS) != 0) {
        error_code = errno;
        if (socket_fd >= 0) {
            close(socket_fd);
        }
        return diagnostic_fail(report, index, FP_DIAGNOSTIC_REASON_LISTENER_UNREACHABLE,
                               error_code, 0, on_event, context);
    }
    close(socket_fd);
    diagnostic_emit(report, index, FP_DIAGNOSTIC_OK, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);

    index = FP_DIAGNOSTIC_FIREWALL;
    diagnostic_emit(report, index, FP_DIAGNOSTIC_RUNNING, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);
    if (!fp_firewall_is_enabled(&config)) {
        return diagnostic_fail(report, index, FP_DIAGNOSTIC_REASON_FIREWALL_INCOMPLETE,
                               0, 0, on_event, context);
    }
    diagnostic_emit(report, index, FP_DIAGNOSTIC_OK, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);

    index = FP_DIAGNOSTIC_PROXY_TCP;
    diagnostic_emit(report, index, FP_DIAGNOSTIC_RUNNING, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);
    socket_fd = diagnostic_proxy_tcp(&config, &error_code);
    if (socket_fd < 0) {
        return diagnostic_fail(report, index, FP_DIAGNOSTIC_REASON_PROXY_UNREACHABLE,
                               error_code, 0, on_event, context);
    }
    diagnostic_emit(report, index, FP_DIAGNOSTIC_OK, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);

    index = FP_DIAGNOSTIC_SOCKS5;
    diagnostic_emit(report, index, FP_DIAGNOSTIC_RUNNING, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);
    reason = diagnostic_socks_handshake(socket_fd, &error_code, &detail_code);
    close(socket_fd);
    if (reason != FP_DIAGNOSTIC_REASON_NONE) {
        return diagnostic_fail(report, index, reason, error_code, detail_code, on_event, context);
    }
    diagnostic_emit(report, index, FP_DIAGNOSTIC_OK, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);

    index = FP_DIAGNOSTIC_DNS;
    diagnostic_emit(report, index, FP_DIAGNOSTIC_RUNNING, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);
    if (resolve_ipv4(diagnostic_host, diagnostic_service, &addresses, cancel_flag,
                     &resolver_error) != 0 || addresses == NULL) {
        if (diagnostic_cancel(report, index, on_event, context, cancel_flag)) {
            return -1;
        }
        return diagnostic_fail(report, index, FP_DIAGNOSTIC_REASON_DNS_FAILED,
                               resolver_error, 0, on_event, context);
    }
    diagnostic_emit(report, index, FP_DIAGNOSTIC_OK, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);

    index = FP_DIAGNOSTIC_SOCKS_CONNECT;
    diagnostic_emit(report, index, FP_DIAGNOSTIC_RUNNING, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);
    reason = FP_DIAGNOSTIC_REASON_INTERNAL;
    for (address = addresses; address != NULL; address = address->ai_next) {
        if (address->ai_addrlen < sizeof(destination)) {
            continue;
        }
        memcpy(&destination, address->ai_addr, sizeof(destination));
        error_code = 0;
        detail_code = 0;
        reason = diagnostic_socks_connect(&config, &destination, &error_code,
                                          &detail_code, cancel_flag);
        if (reason == FP_DIAGNOSTIC_REASON_NONE || cancelled(cancel_flag)) {
            break;
        }
    }
    freeaddrinfo(addresses);
    addresses = NULL;
    if (reason != FP_DIAGNOSTIC_REASON_NONE) {
        if (diagnostic_cancel(report, index, on_event, context, cancel_flag)) {
            return -1;
        }
        return diagnostic_fail(report, index, reason, error_code, detail_code,
                               on_event, context);
    }
    diagnostic_emit(report, index, FP_DIAGNOSTIC_OK, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);

    index = FP_DIAGNOSTIC_TRANSPARENT;
    diagnostic_emit(report, index, FP_DIAGNOSTIC_RUNNING, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);
    if (diagnostic_transparent_http(&destination, cancel_flag, &error_code) != 0) {
        if (diagnostic_cancel(report, index, on_event, context, cancel_flag)) {
            return -1;
        }
        return diagnostic_fail(report, index, FP_DIAGNOSTIC_REASON_TRANSPARENT_FAILED,
                               error_code, 0, on_event, context);
    }
    diagnostic_emit(report, index, FP_DIAGNOSTIC_OK, FP_DIAGNOSTIC_REASON_NONE,
                    0, 0, on_event, context);
    report->success = true;
    diagnostic_done(report, on_event, context);
    return 0;
}

int fp_test_run(enum fp_test_mode mode, struct fp_test_report *report,
                fp_test_event_callback on_event, void *context,
                atomic_bool *cancel_flag) {
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
