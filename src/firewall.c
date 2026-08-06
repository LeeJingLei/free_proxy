#include "free_proxy.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *iptables_binary(void) {
    if (access("/usr/sbin/iptables", X_OK) == 0) {
        return "/usr/sbin/iptables";
    }
    if (access("/sbin/iptables", X_OK) == 0) {
        return "/sbin/iptables";
    }
    if (access("/usr/sbin/iptables-nft", X_OK) == 0) {
        return "/usr/sbin/iptables-nft";
    }
    if (access("/sbin/iptables-nft", X_OK) == 0) {
        return "/sbin/iptables-nft";
    }
    return "iptables";
}

static int run_iptables(char *const arguments[]) {
    pid_t pid = fork();
    int status;

    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        char *argv_copy[32];
        size_t count = 0;

        if (freopen("/dev/null", "w", stdout) == NULL ||
            freopen("/dev/null", "w", stderr) == NULL) {
            _exit(127);
        }
        while (arguments[count] != NULL && count + 1 < sizeof(argv_copy) / sizeof(argv_copy[0])) {
            argv_copy[count] = arguments[count];
            ++count;
        }
        argv_copy[count] = NULL;
        argv_copy[0] = (char *)iptables_binary();
        execvp(argv_copy[0], argv_copy);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int chain_exists(void) {
    char *const arguments[] = {"iptables", "-w", "-t", "nat", "-S", FP_CHAIN, NULL};
    return run_iptables(arguments) == 0;
}

static int output_jump_exists(void) {
    char *const arguments[] = {
        "iptables", "-w", "-t", "nat", "-C", "OUTPUT", "-p", "tcp", "-j", FP_CHAIN, NULL
    };
    return run_iptables(arguments) == 0;
}

int fp_firewall_is_enabled(const struct fp_config *config) {
    char proxy_address[INET_ADDRSTRLEN];
    char port[6];
    char *const proxy_rule[] = {
        "iptables", "-w", "-t", "nat", "-C", FP_CHAIN, "-d", proxy_address, "-j", "RETURN", NULL
    };
    char *const loopback_rule[] = {
        "iptables", "-w", "-t", "nat", "-C", FP_CHAIN, "-d", "127.0.0.0/8", "-j", "RETURN", NULL
    };
    char *const redirect_rule[] = {
        "iptables", "-w", "-t", "nat", "-C", FP_CHAIN, "-p", "tcp", "-j", "REDIRECT",
        "--to-ports", port, NULL
    };

    if (inet_ntop(AF_INET, &config->proxy_addr, proxy_address, sizeof(proxy_address)) == NULL ||
        snprintf(port, sizeof(port), "%u", FP_LISTEN_PORT) < 0) {
        return 0;
    }
    return chain_exists() && output_jump_exists() && run_iptables(proxy_rule) == 0 &&
           run_iptables(loopback_rule) == 0 && run_iptables(redirect_rule) == 0;
}

int fp_firewall_enable(const struct fp_config *config) {
    char proxy_address[INET_ADDRSTRLEN];
    char port[6];
    char *create_chain[] = {"iptables", "-w", "-t", "nat", "-N", FP_CHAIN, NULL};
    char *flush_chain[] = {"iptables", "-w", "-t", "nat", "-F", FP_CHAIN, NULL};
    char *exclude_proxy[] = {
        "iptables", "-w", "-t", "nat", "-A", FP_CHAIN, "-d", proxy_address, "-j", "RETURN", NULL
    };
    char *exclude_loopback[] = {
        "iptables", "-w", "-t", "nat", "-A", FP_CHAIN, "-d", "127.0.0.0/8", "-j", "RETURN", NULL
    };
    char *redirect[] = {
        "iptables", "-w", "-t", "nat", "-A", FP_CHAIN, "-p", "tcp", "-j", "REDIRECT",
        "--to-ports", port, NULL
    };
    char *check_jump[] = {
        "iptables", "-w", "-t", "nat", "-C", "OUTPUT", "-p", "tcp", "-j", FP_CHAIN, NULL
    };
    char *add_jump[] = {
        "iptables", "-w", "-t", "nat", "-I", "OUTPUT", "1", "-p", "tcp", "-j", FP_CHAIN, NULL
    };

    if (inet_ntop(AF_INET, &config->proxy_addr, proxy_address, sizeof(proxy_address)) == NULL ||
        snprintf(port, sizeof(port), "%u", FP_LISTEN_PORT) < 0) {
        return -1;
    }
    if (!chain_exists() && run_iptables(create_chain) != 0) {
        return -1;
    }
    if (run_iptables(flush_chain) != 0 || run_iptables(exclude_proxy) != 0 ||
        run_iptables(exclude_loopback) != 0) {
        (void)fp_firewall_disable();
        return -1;
    }
    if (run_iptables(redirect) != 0) {
        (void)fp_firewall_disable();
        return -1;
    }
    if (run_iptables(check_jump) != 0 && run_iptables(add_jump) != 0) {
        (void)fp_firewall_disable();
        return -1;
    }
    return 0;
}

int fp_firewall_disable(void) {
    char *remove_jump[] = {
        "iptables", "-w", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", FP_CHAIN, NULL
    };
    char *flush_chain[] = {"iptables", "-w", "-t", "nat", "-F", FP_CHAIN, NULL};
    char *delete_chain[] = {"iptables", "-w", "-t", "nat", "-X", FP_CHAIN, NULL};

    while (output_jump_exists()) {
        if (run_iptables(remove_jump) != 0) {
            return -1;
        }
    }
    if (!chain_exists()) {
        return 0;
    }
    return run_iptables(flush_chain) == 0 && run_iptables(delete_chain) == 0 ? 0 : -1;
}
