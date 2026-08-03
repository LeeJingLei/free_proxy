#include "free_proxy.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static int run_iptables(char *const arguments[], int quiet) {
    pid_t pid = fork();
    int status;

    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        (void)quiet;
        if (freopen("/dev/null", "w", stdout) == NULL ||
            freopen("/dev/null", "w", stderr) == NULL) {
            _exit(127);
        }
        execvp("iptables", arguments);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int chain_exists(void) {
    char *const arguments[] = {"iptables", "-t", "nat", "-S", FP_CHAIN, NULL};
    return run_iptables(arguments, 1) == 0;
}

int fp_firewall_is_enabled(void) {
    char *const arguments[] = {
        "iptables", "-t", "nat", "-C", "OUTPUT", "-p", "tcp", "-j", FP_CHAIN, NULL
    };
    return run_iptables(arguments, 1) == 0;
}

int fp_firewall_enable(const struct fp_config *config) {
    char proxy_address[INET_ADDRSTRLEN];
    char port[6];
    char *create_chain[] = {"iptables", "-t", "nat", "-N", FP_CHAIN, NULL};
    char *flush_chain[] = {"iptables", "-t", "nat", "-F", FP_CHAIN, NULL};
    char *exclude_proxy[] = {
        "iptables", "-t", "nat", "-A", FP_CHAIN, "-d", proxy_address, "-j", "RETURN", NULL
    };
    char *exclude_loopback[] = {
        "iptables", "-t", "nat", "-A", FP_CHAIN, "-d", "127.0.0.0/8", "-j", "RETURN", NULL
    };
    char *redirect[] = {
        "iptables", "-t", "nat", "-A", FP_CHAIN, "-p", "tcp", "-j", "REDIRECT",
        "--to-ports", port, NULL
    };
    char *check_jump[] = {
        "iptables", "-t", "nat", "-C", "OUTPUT", "-p", "tcp", "-j", FP_CHAIN, NULL
    };
    char *add_jump[] = {
        "iptables", "-t", "nat", "-I", "OUTPUT", "1", "-p", "tcp", "-j", FP_CHAIN, NULL
    };

    if (inet_ntop(AF_INET, &config->proxy_addr, proxy_address, sizeof(proxy_address)) == NULL ||
        snprintf(port, sizeof(port), "%u", FP_LISTEN_PORT) < 0) {
        return -1;
    }
    if (!chain_exists() && run_iptables(create_chain, 0) != 0) {
        return -1;
    }
    if (run_iptables(flush_chain, 0) != 0 || run_iptables(exclude_proxy, 0) != 0 ||
        run_iptables(exclude_loopback, 0) != 0 || run_iptables(redirect, 0) != 0) {
        return -1;
    }
    if (run_iptables(check_jump, 1) != 0 && run_iptables(add_jump, 0) != 0) {
        return -1;
    }
    return 0;
}

int fp_firewall_disable(void) {
    char *remove_jump[] = {
        "iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", FP_CHAIN, NULL
    };
    char *flush_chain[] = {"iptables", "-t", "nat", "-F", FP_CHAIN, NULL};
    char *delete_chain[] = {"iptables", "-t", "nat", "-X", FP_CHAIN, NULL};

    while (fp_firewall_is_enabled()) {
        if (run_iptables(remove_jump, 0) != 0) {
            return -1;
        }
    }
    if (!chain_exists()) {
        return 0;
    }
    return run_iptables(flush_chain, 0) == 0 && run_iptables(delete_chain, 0) == 0 ? 0 : -1;
}
