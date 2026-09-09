#include "free_proxy.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void test_proxy_parser(void) {
    struct fp_config config;

    memset(&config, 0, sizeof(config));
    assert(fp_parse_proxy("192.168.3.2:10808", &config) == 0);
    assert(config.proxy_port == 10808);
    assert(fp_parse_proxy("invalid:10808", &config) != 0);
    assert(fp_parse_proxy("192.168.3.2:0", &config) != 0);
    assert(fp_parse_proxy("192.168.3.2:65536", &config) != 0);
}

static void test_bypass_parser(void) {
    struct fp_config config;

    memset(&config, 0, sizeof(config));
    assert(fp_parse_bypass_list("192.168.1.25, 10.2.3.4/8", &config) == 0);
    assert(config.bypass_count == 2);
    assert(strcmp(config.bypass[0].text, "192.168.1.25") == 0);
    assert(strcmp(config.bypass[1].text, "10.0.0.0/8") == 0);
    assert(fp_parse_proxy("192.168.3.2:10808", &config) == 0);
    assert(config.bypass_count == 2);
    assert(fp_parse_bypass_list("192.168.1.0/33", &config) != 0);
    assert(fp_parse_bypass_list("not-an-ip", &config) != 0);
    assert(fp_parse_bypass_list("", &config) == 0 && config.bypass_count == 0);
}

static void test_socks5_maximum_domain_reply(void) {
    int sockets[2];
    unsigned char reply[260] = {0x00, 0x03, 0xff};

    memset(reply + 3, 'a', 255);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(write(sockets[0], reply, sizeof(reply)) == (ssize_t)sizeof(reply));
    assert(fp_socks5_drain_bind(sockets[1]) == 0);
    close(sockets[0]);
    close(sockets[1]);
}

static void test_socks5_rejects_unknown_address_type(void) {
    int sockets[2];
    unsigned char reply[] = {0x00, 0x7f};

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(write(sockets[0], reply, sizeof(reply)) == (ssize_t)sizeof(reply));
    assert(fp_socks5_drain_bind(sockets[1]) != 0);
    close(sockets[0]);
    close(sockets[1]);
}

static long long monotonic_ms(void) {
    struct timespec value;

    assert(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    return (long long)value.tv_sec * 1000LL + (long long)value.tv_nsec / 1000000LL;
}

static int read_http_request(int socket_fd) {
    char request[2048];
    size_t used = 0;

    while (used < sizeof(request)) {
        ssize_t received = recv(socket_fd, request + used, sizeof(request) - used, 0);
        size_t index;

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return 0;
        }
        used += (size_t)received;
        for (index = 0; index + 3 < used; ++index) {
            if (request[index] == '\r' && request[index + 1] == '\n' &&
                request[index + 2] == '\r' && request[index + 3] == '\n') {
                return used >= 5 && memcmp(request, "HEAD ", 5) == 0;
            }
        }
    }
    return 0;
}

static void run_delayed_http_server(int listener_fd) {
    static const char response[] =
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const struct timespec delay = {.tv_sec = 0, .tv_nsec = 150000000L};
    int client_fd;
    size_t sent = 0;

    alarm(5);
    client_fd = accept(listener_fd, NULL, NULL);
    if (client_fd < 0 || !read_http_request(client_fd)) {
        _exit(1);
    }
    while (nanosleep(&delay, NULL) != 0 && errno == EINTR) {
    }
    while (sent < sizeof(response) - 1) {
        ssize_t written =
            send(client_fd, response + sent, sizeof(response) - 1 - sent, MSG_NOSIGNAL);

        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            _exit(1);
        }
        sent += (size_t)written;
    }
    close(client_fd);
    close(listener_fd);
    _exit(0);
}

static void test_web_probe_waits_for_real_http_response(void) {
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = 0,
    };
    socklen_t address_length = sizeof(address);
    atomic_bool cancel_flag;
    int listener_fd;
    int latency_ms = -1;
    int probe_result;
    int child_status;
    pid_t server_pid;
    pid_t waited_pid;
    long long start;
    long long elapsed;

    listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener_fd >= 0);
    assert(bind(listener_fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(listen(listener_fd, 1) == 0);
    assert(getsockname(listener_fd, (struct sockaddr *)&address, &address_length) == 0);

    server_pid = fork();
    assert(server_pid >= 0);
    if (server_pid == 0) {
        run_delayed_http_server(listener_fd);
    }
    close(listener_fd);

    atomic_init(&cancel_flag, false);
    start = monotonic_ms();
    probe_result =
        fp_web_probe("127.0.0.1", ntohs(address.sin_port), &latency_ms, &cancel_flag);
    elapsed = monotonic_ms() - start;
    if (probe_result != 0) {
        (void)kill(server_pid, SIGTERM);
    }
    do {
        waited_pid = waitpid(server_pid, &child_status, 0);
    } while (waited_pid < 0 && errno == EINTR);
    assert(waited_pid == server_pid);
    assert(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    assert(probe_result == 0);
    assert(latency_ms >= 120);
    assert(elapsed >= 120);
}

int main(void) {
    test_proxy_parser();
    test_bypass_parser();
    test_socks5_maximum_domain_reply();
    test_socks5_rejects_unknown_address_type();
    test_web_probe_waits_for_real_http_response();
    puts("unit tests passed");
    return 0;
}
