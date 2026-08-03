#include "free_proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/netfilter_ipv4.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <unistd.h>

static volatile sig_atomic_t keep_running = 1;
static volatile sig_atomic_t active_clients = 0;

static void stop_proxy(int signal_number) {
    (void)signal_number;
    keep_running = 0;
}

static void reap_clients(int signal_number) {
    int saved_errno = errno;

    (void)signal_number;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
        if (active_clients > 0) {
            --active_clients;
        }
    }
    errno = saved_errno;
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

static int connect_socks(const struct fp_config *config, const struct sockaddr_in *destination,
                         int connect_timeout_ms, int io_timeout_ms) {
    int socket_fd;
    unsigned char greeting[] = {0x05, 0x01, 0x00};
    unsigned char response[2];
    unsigned char request[10] = {0x05, 0x01, 0x00, 0x01};
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
    memcpy(request + 4, &destination->sin_addr, 4);
    memcpy(request + 8, &destination->sin_port, 2);
    if (write_all(socket_fd, request, sizeof(request)) != 0 ||
        read_all(socket_fd, response, sizeof(response)) != 0 || response[0] != 0x05 ||
        response[1] != 0x00) {
        close(socket_fd);
        return -1;
    }
    if (fp_socks5_drain_bind(socket_fd) != 0) {
        close(socket_fd);
        return -1;
    }
    return socket_fd;
}

int fp_test_proxy(void) {
    struct fp_config config;
    struct sockaddr_in listener = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(FP_LISTEN_PORT),
    };
    struct sockaddr_in destination = {
        .sin_family = AF_INET,
        .sin_port = htons(443),
    };
    int listener_fd;
    int socket_fd;

    if (fp_config_load(&config) != 0 || !fp_firewall_is_enabled(&config) ||
        inet_pton(AF_INET, "1.1.1.1", &destination.sin_addr) != 1) {
        return -1;
    }
    listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listener_fd < 0 ||
        connect_with_timeout(listener_fd, (struct sockaddr *)&listener, sizeof(listener),
                             FP_TEST_TIMEOUT_MS) != 0) {
        if (listener_fd >= 0) {
            close(listener_fd);
        }
        return -1;
    }
    close(listener_fd);
    socket_fd = connect_socks(&config, &destination, FP_TEST_TIMEOUT_MS, FP_TEST_TIMEOUT_MS);
    if (socket_fd < 0) {
        return -1;
    }
    close(socket_fd);
    return 0;
}

static void relay(int client_fd, int upstream_fd) {
    struct pollfd descriptors[2] = {
        {.fd = client_fd, .events = POLLIN},
        {.fd = upstream_fd, .events = POLLIN},
    };
    unsigned char buffer[16384];

    while (keep_running) {
        int poll_result = poll(descriptors, 2, FP_IDLE_TIMEOUT_MS);

        if (poll_result <= 0) {
            if (poll_result < 0 && errno == EINTR) {
                continue;
            }
            return;
        }
        for (size_t index = 0; index < 2; ++index) {
            int source = descriptors[index].fd;
            int target = descriptors[1 - index].fd;
            ssize_t received;

            if ((descriptors[index].revents & (POLLIN | POLLHUP)) == 0) {
                continue;
            }
            received = recv(source, buffer, sizeof(buffer), 0);
            if (received <= 0) {
                shutdown(target, SHUT_WR);
                descriptors[index].events = 0;
                continue;
            }
            if (write_all(target, buffer, (size_t)received) != 0) {
                return;
            }
        }
        if (descriptors[0].events == 0 && descriptors[1].events == 0) {
            return;
        }
    }
}

static int drop_client_privileges(void) {
    if (geteuid() != 0) {
        return 0;
    }
    return setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0 ? 0 : -1;
}

static void handle_client(int client_fd, const struct fp_config *config) {
    struct sockaddr_in destination;
    socklen_t destination_length = sizeof(destination);
    int upstream_fd;

    if (set_socket_timeouts(client_fd, FP_IO_TIMEOUT_MS) != 0 ||
        getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST, &destination, &destination_length) != 0) {
        close(client_fd);
        return;
    }
    upstream_fd = connect_socks(config, &destination, FP_CONNECT_TIMEOUT_MS, FP_IO_TIMEOUT_MS);
    if (upstream_fd >= 0) {
        relay(client_fd, upstream_fd);
        close(upstream_fd);
    }
    close(client_fd);
}

static void signal_ready(int ready_fd, char value) {
    if (ready_fd >= 0) {
        if (write(ready_fd, &value, 1) < 0) {
            /* Parent will treat a missing readiness signal as startup failure. */
        }
        (void)close(ready_fd);
    }
}

int fp_proxy_run(const struct fp_config *config, int ready_fd) {
    int listener;
    int option = 1;
    struct sockaddr_in listen_address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(FP_LISTEN_PORT),
    };

    struct sigaction child_action = {.sa_handler = reap_clients};
    sigset_t child_signal_mask;

    keep_running = 1;
    active_clients = 0;
    signal(SIGTERM, stop_proxy);
    signal(SIGINT, stop_proxy);
    sigemptyset(&child_action.sa_mask);
    child_action.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    (void)sigaction(SIGCHLD, &child_action, NULL);
    sigemptyset(&child_signal_mask);
    sigaddset(&child_signal_mask, SIGCHLD);
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0 || setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) != 0 ||
        bind(listener, (struct sockaddr *)&listen_address, sizeof(listen_address)) != 0 ||
        listen(listener, 128) != 0) {
        if (listener >= 0) {
            close(listener);
        }
        signal_ready(ready_fd, 'E');
        return -1;
    }
    if (fp_write_pid(config) != 0 || fp_firewall_enable(config) != 0) {
        close(listener);
        (void)fp_firewall_disable();
        signal_ready(ready_fd, 'E');
        return -1;
    }
    signal_ready(ready_fd, 'R');
    while (keep_running) {
        struct pollfd listener_poll = {.fd = listener, .events = POLLIN};
        int poll_result = poll(&listener_poll, 1, 500);
        int client_fd;
        pid_t child;
        sigset_t previous_signal_mask;

        if (poll_result == 0) {
            continue;
        }
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(listener);
            fp_remove_pid();
            return -1;
        }
        client_fd = accept(listener, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(listener);
            fp_remove_pid();
            return -1;
        }
        if (active_clients >= FP_MAX_CLIENTS) {
            close(client_fd);
            continue;
        }
        if (sigprocmask(SIG_BLOCK, &child_signal_mask, &previous_signal_mask) != 0) {
            close(client_fd);
            continue;
        }
        child = fork();
        if (child == 0) {
            pid_t parent_pid = getppid();
            close(listener);
            (void)signal(SIGTERM, SIG_DFL);
            (void)signal(SIGINT, SIG_DFL);
            (void)sigprocmask(SIG_SETMASK, &previous_signal_mask, NULL);
            if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || getppid() != parent_pid ||
                drop_client_privileges() != 0) {
                close(client_fd);
                _exit(1);
            }
            handle_client(client_fd, config);
            _exit(0);
        }
        if (child > 0) {
            ++active_clients;
        }
        (void)sigprocmask(SIG_SETMASK, &previous_signal_mask, NULL);
        close(client_fd);
    }
    close(listener);
    fp_remove_pid();
    return 0;
}
