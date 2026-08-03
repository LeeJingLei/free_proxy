#include "free_proxy.h"

#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>

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

int fp_socks5_drain_bind(int socket_fd) {
    unsigned char header[2];
    unsigned char discard[257];
    size_t remaining;

    if (read_all(socket_fd, header, sizeof(header)) != 0 || header[0] != 0x00) {
        return -1;
    }
    if (header[1] == 0x01) {
        remaining = 6;
    } else if (header[1] == 0x04) {
        remaining = 18;
    } else if (header[1] == 0x03) {
        if (read_all(socket_fd, discard, 1) != 0) {
            return -1;
        }
        remaining = (size_t)discard[0] + 2;
    } else {
        return -1;
    }
    return read_all(socket_fd, discard, remaining);
}
