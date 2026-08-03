#include "free_proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter_ipv4.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static volatile sig_atomic_t keep_running = 1;

static void stop_proxy(int signal_number) {
    (void)signal_number;
    keep_running = 0;
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

static int connect_socks(const struct fp_config *config, const struct sockaddr_in *destination) {
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
    if (socket_fd < 0 || connect(socket_fd, (struct sockaddr *)&proxy, sizeof(proxy)) != 0 ||
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
    if (response[0] == 0x05) {
        unsigned char discard[256];
        size_t address_length;

        if (read_all(socket_fd, response, 2) != 0) {
            close(socket_fd);
            return -1;
        }
        address_length = response[1] == 0x01 ? 4 : response[1] == 0x04 ? 16 : 0;
        if (response[1] == 0x03) {
            if (read_all(socket_fd, response, 1) != 0) {
                close(socket_fd);
                return -1;
            }
            address_length = response[0];
        }
        if (address_length == 0 || read_all(socket_fd, discard, address_length + 2) != 0) {
            close(socket_fd);
            return -1;
        }
    }
    return socket_fd;
}

static void relay(int client_fd, int upstream_fd) {
    struct pollfd descriptors[2] = {
        {.fd = client_fd, .events = POLLIN},
        {.fd = upstream_fd, .events = POLLIN},
    };
    unsigned char buffer[16384];

    while (poll(descriptors, 2, -1) > 0) {
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

static void handle_client(int client_fd, const struct fp_config *config) {
    struct sockaddr_in destination;
    socklen_t destination_length = sizeof(destination);
    int upstream_fd;

    if (getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST, &destination, &destination_length) != 0) {
        close(client_fd);
        return;
    }
    upstream_fd = connect_socks(config, &destination);
    if (upstream_fd >= 0) {
        relay(client_fd, upstream_fd);
        close(upstream_fd);
    }
    close(client_fd);
}

int fp_proxy_run(const struct fp_config *config) {
    int listener;
    int option = 1;
    struct sockaddr_in listen_address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(FP_LISTEN_PORT),
    };

    signal(SIGTERM, stop_proxy);
    signal(SIGINT, stop_proxy);
    signal(SIGCHLD, SIG_IGN);
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0 || setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) != 0 ||
        bind(listener, (struct sockaddr *)&listen_address, sizeof(listen_address)) != 0 ||
        listen(listener, 128) != 0) {
        perror("start transparent proxy");
        if (listener >= 0) {
            close(listener);
        }
        return -1;
    }
    if (fp_write_pid() != 0) {
        close(listener);
        return -1;
    }
    while (keep_running) {
        int client_fd = accept(listener, NULL, NULL);
        pid_t child;

        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            break;
        }
        child = fork();
        if (child == 0) {
            close(listener);
            handle_client(client_fd, config);
            _exit(0);
        }
        close(client_fd);
    }
    close(listener);
    fp_remove_pid();
    return 0;
}
