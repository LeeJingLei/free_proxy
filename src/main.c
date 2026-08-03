#include "free_proxy.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void print_usage(const char *program_name) {
    fprintf(stderr,
            "Usage:\n"
            "  %s\n"
            "  %s enable --proxy IPv4:PORT\n"
            "  %s disable\n"
            "  %s status\n"
            "  %s autostart enable|disable\n",
            program_name, program_name, program_name, program_name, program_name);
}

static int require_root(void) {
    if (geteuid() != 0) {
        fprintf(stderr, "free_proxy must run as root (try sudo)\n");
        return -1;
    }
    return 0;
}

static void print_status(void) {
    struct fp_status status;

    fp_collect_status(&status);
    printf("configuration: %s\n", status.config_present ? "present" : "missing");
    printf("daemon: %s", status.daemon_running ? "running" : "stopped");
    if (status.daemon_pid > 1) {
        printf(" (pid %ld)", (long)status.daemon_pid);
    }
    putchar('\n');
    printf("iptables: %s\n", status.firewall_enabled ? "enabled" : "disabled");
    printf("autostart: %s\n", status.autostart_enabled ? "enabled" : "disabled");
    puts("coverage: IPv4 TCP only; DNS, UDP, and IPv6 are not proxied");
}

int main(int argc, char *argv[]) {
    struct fp_config config;

    if (require_root() != 0) {
        return 1;
    }
    if (argc == 1) {
        return fp_tui_run(argv[0]);
    }
    if (strcmp(argv[1], "enable") == 0) {
        if (argc != 4 || strcmp(argv[2], "--proxy") != 0) {
            print_usage(argv[0]);
            return 2;
        }
        if (fp_enable_proxy(argv[0], argv[3]) != 0) {
            fprintf(stderr, "could not enable proxy; expected a valid IPv4:PORT and iptables\n");
            return 1;
        }
        printf("free_proxy enabled: TCP IPv4 traffic uses SOCKS5 %s\n", argv[3]);
        return 0;
    }
    if (strcmp(argv[1], "disable") == 0) {
        if (fp_disable_proxy() != 0) {
            fprintf(stderr, "free_proxy cleanup was incomplete\n");
            return 1;
        }
        puts("free_proxy disabled");
        return 0;
    }
    if (strcmp(argv[1], "status") == 0) {
        print_status();
        return 0;
    }
    if (strcmp(argv[1], "run") == 0) {
        if (argc != 2 || fp_config_load(&config) != 0) {
            return 1;
        }
        if (fp_firewall_enable(&config) != 0) {
            fprintf(stderr, "could not install iptables rules\n");
            return 1;
        }
        {
            int result = fp_proxy_run(&config);
            (void)signal(SIGCHLD, SIG_DFL);
            (void)fp_firewall_disable();
            return result == 0 ? 0 : 1;
        }
    }
    if (strcmp(argv[1], "autostart") == 0 && argc == 3) {
        if (strcmp(argv[2], "enable") == 0) {
            return fp_autostart_enable() == 0 ? 0 : 1;
        }
        if (strcmp(argv[2], "disable") == 0) {
            return fp_autostart_disable() == 0 ? 0 : 1;
        }
    }
    print_usage(argv[0]);
    return 2;
}
