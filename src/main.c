#include "free_proxy.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_usage(const char *program_name) {
    fprintf(stderr,
            "Usage:\n"
            "  %s\n"
            "  %s enable --proxy IPv4:PORT\n"
            "  %s disable\n"
            "  %s status\n"
            "  %s autostart enable|disable\n"
            "  %s uninstall --yes\n",
            program_name, program_name, program_name, program_name, program_name, program_name);
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
        return fp_tui_run();
    }
    if (strcmp(argv[1], "enable") == 0) {
        if (argc != 4 || strcmp(argv[2], "--proxy") != 0) {
            print_usage(argv[0]);
            return 2;
        }
        if (fp_enable_proxy(argv[3]) != 0) {
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
    if (strcmp(argv[1], "uninstall") == 0) {
        if (argc != 3 || strcmp(argv[2], "--yes") != 0) {
            fprintf(stderr, "refusing uninstall without --yes\n");
            return 2;
        }
        if (fp_uninstall() != 0) {
            fprintf(stderr, "free_proxy uninstall was incomplete\n");
            return 1;
        }
        puts("free_proxy uninstalled");
        return 0;
    }
    if (strcmp(argv[1], "status") == 0) {
        print_status();
        return 0;
    }
    if (strcmp(argv[1], "run") == 0) {
        int ready_fd = -1;
        bool ready_argument_valid = argc == 2;

        if (argc == 4 && strcmp(argv[2], "--ready-fd") == 0) {
            char *end = NULL;
            long value = strtol(argv[3], &end, 10);

            if (*end == '\0' && value >= 0 && value <= 1024) {
                ready_fd = (int)value;
                ready_argument_valid = true;
            }
        } else if (argc != 2) {
            return 1;
        }
        if (!ready_argument_valid || fp_config_load(&config) != 0) {
            if (ready_fd >= 0) {
                if (write(ready_fd, "E", 1) < 0) {
                    /* Parent will time out if the readiness pipe is unusable. */
                }
                (void)close(ready_fd);
            }
            return 1;
        }
        {
            int result = fp_proxy_run(&config, ready_fd);
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
