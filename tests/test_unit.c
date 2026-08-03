#include "free_proxy.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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

int main(void) {
    test_proxy_parser();
    test_socks5_maximum_domain_reply();
    test_socks5_rejects_unknown_address_type();
    puts("unit tests passed");
    return 0;
}
