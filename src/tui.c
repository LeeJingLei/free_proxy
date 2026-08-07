#include "free_proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <locale.h>
#include <ncursesw/ncurses.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MIN_ROWS 24
#define MIN_COLS 66

struct ui_text {
    const char *title;
    const char *terminal_small;
    const char *resize;
    const char *proxy;
    const char *forwarder;
    const char *iptables;
    const char *autostart;
    const char *configured;
    const char *invalid;
    const char *running;
    const char *stopped;
    const char *enabled;
    const char *disabled;
    const char *commands;
    const char *start;
    const char *enable;
    const char *disable;
    const char *startup;
    const char *monitor;
    const char *test;
    const char *uninstall;
    const char *language;
    const char *refresh;
    const char *quit;
    const char *coverage;
    const char *prompt;
    const char *initial_message;
    const char *input_cancelled;
    const char *enable_failed;
    const char *disable_failed;
    const char *startup_failed;
    const char *language_failed;
};

static const struct ui_text UI_TEXT[] = {
    [FP_UI_LANGUAGE_ZH] =
        {"free_proxy  |  透明 SOCKS5 代理控制台",
         "终端尺寸不足：至少需要 %d 列、%d 行。",
         "请调整终端尺寸，或按 q 退出。",
         "SOCKS5 代理",
         "转发服务",
         "iptables",
         "开机自启",
         "未配置",
         "配置无效",
         "运行中",
         "已停止",
         "已启用",
         "已禁用",
         "操作",
         "s  启用已保存的代理配置",
         "e  修改 IPv4:端口 并启用代理",
         "d  停用代理",
         "a  切换开机自启",
         "m  流量与连接监控",
         "t  打开网络测试页",
         "u  卸载 free_proxy",
         "l  切换语言（中文/English）",
         "r  立即刷新",
         "q  退出",
         "范围：仅 IPv4 TCP；DNS、UDP 和 IPv6 不经过代理。",
         "SOCKS5 服务器（IPv4:端口）：",
         "按 s 启用已保存配置，或按 e 修改代理地址。",
         "已取消输入。",
         "无法启用代理，请检查地址和系统配置。",
         "无法完全停用代理。",
         "无法更改开机自启；请先执行 sudo make install。",
         "无法保存语言设置。"},
    [FP_UI_LANGUAGE_EN] =
        {"free_proxy  |  Transparent SOCKS5 controller",
         "Terminal too small. Need at least %d columns and %d rows.",
         "Resize the terminal or press q to exit.",
         "SOCKS5 proxy",
         "Forwarder",
         "iptables",
         "Boot startup",
         "not configured",
         "invalid configuration",
         "running",
         "stopped",
         "enabled",
         "disabled",
         "Commands",
         "s  Enable saved proxy configuration",
         "e  Change IPv4:PORT and enable proxy",
         "d  Disable proxy",
         "a  Toggle boot startup",
         "m  Traffic and connection monitor",
         "t  Open network test page",
         "u  Uninstall free_proxy",
         "l  Switch language (中文/English)",
         "r  Refresh now",
         "q  Quit",
         "Coverage: IPv4 TCP only. DNS, UDP, and IPv6 are not proxied.",
         "SOCKS5 server (IPv4:PORT): ",
         "Press s to enable saved settings or e to change the proxy.",
         "Proxy input cancelled.",
         "Unable to enable proxy. Check the address and system setup.",
         "Unable to fully disable proxy.",
         "Unable to change boot startup; run sudo make install first.",
         "Unable to save language setting."},
};

static void draw_line(int row, const char *label, const char *value, int active) {
    attron(A_BOLD);
    mvprintw(row, 4, "%-18s", label);
    attroff(A_BOLD);
    if (active) {
        attron(COLOR_PAIR(1) | A_BOLD);
    } else {
        attron(COLOR_PAIR(2));
    }
    printw("%s", value);
    if (active) {
        attroff(COLOR_PAIR(1) | A_BOLD);
    } else {
        attroff(COLOR_PAIR(2));
    }
}

static void draw_screen(const struct fp_status *status, const struct ui_text *text,
                        const char *message) {
    const char *proxy = status->config_valid ? status->proxy :
                        status->config_present ? text->invalid : text->configured;
    char daemon[64];

    erase();
    if (COLS < MIN_COLS || LINES < MIN_ROWS) {
        mvprintw(1, 2, text->terminal_small, MIN_COLS, MIN_ROWS);
        mvprintw(3, 2, "%s", text->resize);
        refresh();
        return;
    }
    attron(A_BOLD | A_UNDERLINE);
    mvprintw(1, 4, "%s", text->title);
    attroff(A_BOLD | A_UNDERLINE);
    mvhline(2, 2, '-', COLS - 4);

    draw_line(4, text->proxy, proxy, status->config_valid);
    if (status->daemon_running) {
        (void)snprintf(daemon, sizeof(daemon), "%s (PID %ld)", text->running,
                       (long)status->daemon_pid);
    } else {
        (void)snprintf(daemon, sizeof(daemon), "%s", text->stopped);
    }
    draw_line(5, text->forwarder, daemon, status->daemon_running);
    draw_line(6, text->iptables, status->firewall_enabled ? text->enabled : text->disabled,
              status->firewall_enabled);
    draw_line(7, text->autostart, status->autostart_enabled ? text->enabled : text->disabled,
              status->autostart_enabled);

    mvhline(8, 2, '-', COLS - 4);
    attron(A_BOLD);
    mvprintw(9, 4, "%s", text->commands);
    attroff(A_BOLD);
    mvprintw(10, 4, "%s", text->start);
    mvprintw(11, 4, "%s", text->enable);
    mvprintw(12, 4, "%s", text->disable);
    mvprintw(13, 4, "%s", text->startup);
    mvprintw(14, 4, "%s", text->monitor);
    mvprintw(15, 4, "%s", text->test);
    mvprintw(16, 4, "%s", text->uninstall);
    mvprintw(17, 4, "%s", text->language);
    mvprintw(18, 4, "%s", text->refresh);
    mvprintw(19, 4, "%s", text->quit);
    mvprintw(20, 4, "%s", text->coverage);

    if (message[0] != '\0') {
        attron(A_BOLD);
        mvprintw(LINES - 2, 4, "%.*s", COLS - 8, message);
        attroff(A_BOLD);
    }
    refresh();
}

struct test_worker_args {
    enum fp_test_mode mode;
    struct fp_test_report *report;
    int event_fd;
    volatile sig_atomic_t *cancel_flag;
};

static void write_test_event(const struct fp_test_progress_event *event, void *context) {
    struct test_worker_args *args = context;
    const unsigned char *cursor = (const unsigned char *)event;
    size_t remaining = sizeof(*event);

    while (remaining > 0) {
        ssize_t written = write(args->event_fd, cursor, remaining);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return;
        }
        cursor += written;
        remaining -= (size_t)written;
    }
}

static void *test_worker_main(void *context) {
    struct test_worker_args *args = context;

    (void)fp_test_run(args->mode, args->report, write_test_event, args, args->cancel_flag);
    return NULL;
}

static int read_test_event(int event_fd, struct fp_test_progress_event *event) {
    unsigned char *cursor = (unsigned char *)event;
    size_t remaining = sizeof(*event);

    while (remaining > 0) {
        ssize_t received = read(event_fd, cursor, remaining);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return -1;
        }
        cursor += received;
        remaining -= (size_t)received;
    }
    return 0;
}

static void draw_test_menu(enum fp_ui_language language) {
    const char *title = language == FP_UI_LANGUAGE_ZH ? "网络测试" : "Network test";
    const char *choose =
        language == FP_UI_LANGUAGE_ZH ? "请选择测试类型：" : "Choose a test type:";
    const char *connectivity =
        language == FP_UI_LANGUAGE_ZH ? "1  网页连通性" : "1  Site connectivity";
    const char *latency =
        language == FP_UI_LANGUAGE_ZH ? "2  延迟测试" : "2  Latency test";
    const char *speed =
        language == FP_UI_LANGUAGE_ZH ? "3  下载测速" : "3  Download speed";
    const char *back =
        language == FP_UI_LANGUAGE_ZH ? "q  返回主界面" : "q  Back to main screen";

    erase();
    attron(A_BOLD | A_UNDERLINE);
    mvprintw(2, 4, "%s", title);
    attroff(A_BOLD | A_UNDERLINE);
    mvhline(3, 2, '-', COLS - 4);
    mvprintw(5, 4, "%s", choose);
    mvprintw(7, 4, "%s", connectivity);
    mvprintw(8, 4, "%s", latency);
    mvprintw(9, 4, "%s", speed);
    attron(A_BOLD);
    mvprintw(LINES - 2, 4, "%s", back);
    attroff(A_BOLD);
    refresh();
}

static void draw_test_progress(enum fp_ui_language language, enum fp_test_mode mode,
                               const struct fp_test_progress_event *event, int cancelling) {
    const char *title = language == FP_UI_LANGUAGE_ZH ? "网络测试" : "Network test";
    const char *hint = language == FP_UI_LANGUAGE_ZH ? "按 q 取消测试" : "Press q to cancel";
    const char *wait = language == FP_UI_LANGUAGE_ZH ? "正在取消…" : "Cancelling…";
    char line[192];
    char detail[160];

    erase();
    attron(A_BOLD | A_UNDERLINE);
    mvprintw(2, 4, "%s", title);
    attroff(A_BOLD | A_UNDERLINE);
    mvhline(3, 2, '-', COLS - 4);

    detail[0] = '\0';
    if (event->phase == FP_TEST_PHASE_PREFLIGHT) {
        (void)snprintf(line, sizeof(line),
                       language == FP_UI_LANGUAGE_ZH ? "正在检查本地转发服务…" :
                                                       "Checking local forwarder…");
    } else if (event->phase == FP_TEST_PHASE_CONNECTIVITY) {
        if (event->state == FP_TEST_SITE_RUNNING) {
            (void)snprintf(line, sizeof(line),
                           language == FP_UI_LANGUAGE_ZH ?
                               "连通性 %zu/%zu：%s (%s)…" :
                               "Connectivity %zu/%zu: %s (%s)…",
                           event->index, event->total, event->name, event->domain);
        } else if (event->state == FP_TEST_SITE_OK) {
            (void)snprintf(line, sizeof(line),
                           language == FP_UI_LANGUAGE_ZH ? "连通性 %zu/%zu：%s  成功" :
                                                           "Connectivity %zu/%zu: %s  OK",
                           event->index, event->total, event->name);
        } else {
            (void)snprintf(line, sizeof(line),
                           language == FP_UI_LANGUAGE_ZH ? "连通性 %zu/%zu：%s  失败" :
                                                           "Connectivity %zu/%zu: %s  failed",
                           event->index, event->total, event->name);
        }
    } else if (event->phase == FP_TEST_PHASE_LATENCY) {
        if (event->state == FP_TEST_SITE_RUNNING) {
            (void)snprintf(line, sizeof(line),
                           language == FP_UI_LANGUAGE_ZH ? "延迟 %zu/%zu：%s (%s)…" :
                                                           "Latency %zu/%zu: %s (%s)…",
                           event->index, event->total, event->name, event->domain);
        } else if (event->state == FP_TEST_SITE_OK) {
            (void)snprintf(line, sizeof(line),
                           language == FP_UI_LANGUAGE_ZH ? "延迟 %zu/%zu：%s  %d ms" :
                                                           "Latency %zu/%zu: %s  %d ms",
                           event->index, event->total, event->name, event->latency_ms);
        } else {
            (void)snprintf(line, sizeof(line),
                           language == FP_UI_LANGUAGE_ZH ? "延迟 %zu/%zu：%s  失败" :
                                                           "Latency %zu/%zu: %s  failed",
                           event->index, event->total, event->name);
        }
    } else if (event->phase == FP_TEST_PHASE_SPEED) {
        if (event->state == FP_TEST_SITE_RUNNING) {
            (void)snprintf(line, sizeof(line),
                           language == FP_UI_LANGUAGE_ZH ?
                               "测速 %zu/%zu：%s（最多 10 MiB）" :
                               "Speed %zu/%zu: %s (up to 10 MiB)",
                           event->index, event->total, event->name);
            (void)snprintf(detail, sizeof(detail),
                           language == FP_UI_LANGUAGE_ZH ?
                               "实时速度：%.2f Mbps    已下载：%zu / %u bytes" :
                               "Live speed: %.2f Mbps    Downloaded: %zu / %u bytes",
                           event->speed_mbps, event->bytes_downloaded, FP_TEST_SPEED_MAX_BYTES);
        } else if (event->state == FP_TEST_SITE_OK) {
            (void)snprintf(line, sizeof(line),
                           language == FP_UI_LANGUAGE_ZH ?
                               "测速 %zu/%zu：%s  完成 %.2f Mbps" :
                               "Speed %zu/%zu: %s  done %.2f Mbps",
                           event->index, event->total, event->name, event->speed_mbps);
            (void)snprintf(detail, sizeof(detail),
                           language == FP_UI_LANGUAGE_ZH ? "下载量：%zu bytes" :
                                                           "Downloaded: %zu bytes",
                           event->bytes_downloaded);
        } else {
            (void)snprintf(line, sizeof(line),
                           language == FP_UI_LANGUAGE_ZH ? "测速 %zu/%zu：%s  失败" :
                                                           "Speed %zu/%zu: %s  failed",
                           event->index, event->total, event->name);
        }
    } else {
        (void)snprintf(line, sizeof(line),
                       language == FP_UI_LANGUAGE_ZH ? "正在汇总结果…" : "Summarizing results…");
    }

    (void)mode;
    mvprintw(6, 4, "%.*s", COLS - 8, line);
    if (detail[0] != '\0') {
        attron(A_BOLD);
        mvprintw(8, 4, "%.*s", COLS - 8, detail);
        attroff(A_BOLD);
    }
    attron(A_BOLD);
    mvprintw(LINES - 2, 4, "%s", cancelling ? wait : hint);
    attroff(A_BOLD);
    refresh();
}

static void draw_test_results(enum fp_ui_language language, const struct fp_test_report *report) {
    const char *heading = language == FP_UI_LANGUAGE_ZH ? "测试结果" : "Test results";
    const char *failed = language == FP_UI_LANGUAGE_ZH ? "失败目标" : "Failed targets";
    const char *none = language == FP_UI_LANGUAGE_ZH ? "无" : "None";
    const char *cancelled = language == FP_UI_LANGUAGE_ZH ? "测试已取消。" : "Test cancelled.";
    const char *preflight =
        language == FP_UI_LANGUAGE_ZH ?
            "预检失败：请确认服务、规则和宿主机 SOCKS5 可用。" :
            "Preflight failed: check the forwarder, rules, and host SOCKS5.";
    const char *continue_text =
        language == FP_UI_LANGUAGE_ZH ? "按任意键返回测试菜单" : "Press any key to return to menu";
    int row = 5;
    size_t index;
    size_t position = 0;
    int latency_sum = 0;
    size_t latency_count = 0;

    erase();
    attron(A_BOLD | A_UNDERLINE);
    mvprintw(2, 4, "%s", heading);
    attroff(A_BOLD | A_UNDERLINE);
    mvhline(3, 2, '-', COLS - 4);

    if (!report->listener_ok) {
        mvprintw(5, 4, "%s", preflight);
    } else {
        if (report->cancelled) {
            mvprintw(row++, 4, "%s", cancelled);
        }
        if (report->mode == FP_TEST_MODE_CONNECTIVITY) {
            mvprintw(row++, 4,
                     language == FP_UI_LANGUAGE_ZH ? "连通性：%zu/%zu 成功" :
                                                     "Connectivity: %zu/%zu passed",
                     report->sites_passed, report->site_count);
        } else if (report->mode == FP_TEST_MODE_LATENCY) {
            for (index = 0; index < report->site_count; ++index) {
                if (report->sites[index].state == FP_TEST_SITE_OK &&
                    report->sites[index].latency_ms >= 0) {
                    latency_sum += report->sites[index].latency_ms;
                    ++latency_count;
                }
            }
            if (latency_count > 0) {
                mvprintw(row++, 4,
                         language == FP_UI_LANGUAGE_ZH ?
                             "延迟：%zu/%zu 成功，平均 %d ms" :
                             "Latency: %zu/%zu passed, avg %d ms",
                         report->sites_passed, report->site_count,
                         latency_sum / (int)latency_count);
            } else {
                mvprintw(row++, 4,
                         language == FP_UI_LANGUAGE_ZH ? "延迟：%zu/%zu 成功" :
                                                         "Latency: %zu/%zu passed",
                         report->sites_passed, report->site_count);
            }
            for (index = 0; index < report->site_count && row < LINES - 5; ++index) {
                const struct fp_test_site_result *site = &report->sites[index];

                if (site->state == FP_TEST_SITE_OK) {
                    mvprintw(row++, 6, "%-18s %4d ms", site->name, site->latency_ms);
                } else if (site->state == FP_TEST_SITE_FAIL) {
                    mvprintw(row++, 6, "%-18s FAIL", site->name);
                }
            }
        } else {
            mvprintw(row++, 4,
                     language == FP_UI_LANGUAGE_ZH ?
                         "测速：%zu/%zu 成功，峰值 %.2f Mbps" :
                         "Speed: %zu/%zu passed, peak %.2f Mbps",
                     report->speed_passed, report->speed_count, report->best_speed_mbps);
            for (index = 0; index < report->speed_count && row < LINES - 5; ++index) {
                const struct fp_test_site_result *item = &report->speed[index];
                const char *mark = item->state == FP_TEST_SITE_OK        ? "OK" :
                                   item->state == FP_TEST_SITE_FAIL      ? "FAIL" :
                                   item->state == FP_TEST_SITE_CANCELLED ? "SKIP" :
                                                                          "...";

                if (item->state == FP_TEST_SITE_OK) {
                    mvprintw(row++, 6, "%-4s %-18s %6.2f Mbps  (%zu bytes)", mark, item->name,
                             item->speed_mbps, item->bytes_downloaded);
                } else if (item->state != FP_TEST_SITE_PENDING) {
                    mvprintw(row++, 6, "%-4s %-18s", mark, item->name);
                }
            }
        }
        if (row < LINES - 3) {
            attron(A_BOLD);
            mvprintw(row++, 4, "%s:", failed);
            attroff(A_BOLD);
            if (report->failures[0] == '\0') {
                mvprintw(row, 4, "%s", none);
            } else {
                while (report->failures[position] != '\0' && row < LINES - 3) {
                    size_t remaining = strlen(report->failures + position);
                    int width = COLS - 8;
                    int length = (int)(remaining > (size_t)width ? (size_t)width : remaining);

                    mvprintw(row++, 4, "%.*s", length, report->failures + position);
                    position += (size_t)length;
                }
            }
        }
    }

    attron(A_BOLD);
    mvprintw(LINES - 2, 4, "%s", continue_text);
    attroff(A_BOLD);
    refresh();
    timeout(-1);
    (void)getch();
}

static void run_selected_test(enum fp_ui_language language, enum fp_test_mode mode, char *message,
                              size_t message_size) {
    struct fp_test_report report;
    struct fp_test_progress_event event;
    struct test_worker_args args;
    pthread_t worker;
    volatile sig_atomic_t cancel_flag = 0;
    int pipe_fds[2];
    int cancelling = 0;
    int finished = 0;

    memset(&report, 0, sizeof(report));
    memset(&event, 0, sizeof(event));
    event.phase = FP_TEST_PHASE_PREFLIGHT;
    event.index = 1;
    event.total = 1;

    if (pipe(pipe_fds) != 0) {
        (void)snprintf(message, message_size,
                       language == FP_UI_LANGUAGE_ZH ? "无法启动测试。" : "Unable to start test.");
        return;
    }

    args.mode = mode;
    args.report = &report;
    args.event_fd = pipe_fds[1];
    args.cancel_flag = &cancel_flag;
    draw_test_progress(language, mode, &event, 0);
    if (pthread_create(&worker, NULL, test_worker_main, &args) != 0) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        (void)snprintf(message, message_size,
                       language == FP_UI_LANGUAGE_ZH ? "无法启动测试。" : "Unable to start test.");
        return;
    }

    timeout(-1);
    nodelay(stdscr, TRUE);
    while (!finished) {
        struct pollfd descriptors[1] = {{.fd = pipe_fds[0], .events = POLLIN}};
        int key = getch();
        int poll_result;

        if ((key == 'q' || key == 'Q') && !cancelling) {
            cancel_flag = 1;
            cancelling = 1;
            draw_test_progress(language, mode, &event, 1);
        }
        poll_result = poll(descriptors, 1, 100);
        if (poll_result > 0 && (descriptors[0].revents & POLLIN) != 0) {
            if (read_test_event(pipe_fds[0], &event) == 0) {
                if (event.phase == FP_TEST_PHASE_DONE) {
                    finished = 1;
                } else {
                    draw_test_progress(language, mode, &event, cancelling);
                }
            } else {
                finished = 1;
            }
        } else if (poll_result < 0 && errno != EINTR) {
            finished = 1;
        }
    }
    nodelay(stdscr, FALSE);
    (void)pthread_join(worker, NULL);
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    draw_test_results(language, &report);

    if (!report.listener_ok) {
        (void)snprintf(message, message_size,
                       language == FP_UI_LANGUAGE_ZH ?
                           "测试失败：请确认服务、规则和宿主机 SOCKS5 可用。" :
                           "Test failed: check the forwarder, rules, and host SOCKS5.");
    } else if (report.cancelled) {
        (void)snprintf(message, message_size,
                       language == FP_UI_LANGUAGE_ZH ? "测试已取消。" : "Test cancelled.");
    } else if (mode == FP_TEST_MODE_SPEED) {
        (void)snprintf(message, message_size,
                       language == FP_UI_LANGUAGE_ZH ?
                           "测速完成：%zu/%zu，峰值 %.2f Mbps。" :
                           "Speed test done: %zu/%zu, peak %.2f Mbps.",
                       report.speed_passed, report.speed_count, report.best_speed_mbps);
    } else if (mode == FP_TEST_MODE_LATENCY) {
        (void)snprintf(message, message_size,
                       language == FP_UI_LANGUAGE_ZH ? "延迟测试完成：%zu/%zu。" :
                                                       "Latency test done: %zu/%zu.",
                       report.sites_passed, report.site_count);
    } else {
        (void)snprintf(message, message_size,
                       language == FP_UI_LANGUAGE_ZH ? "连通性测试完成：%zu/%zu。" :
                                                       "Connectivity test done: %zu/%zu.",
                       report.sites_passed, report.site_count);
    }
}

static void run_test_page(enum fp_ui_language language, char *message, size_t message_size) {
    timeout(-1);
    for (;;) {
        int key;

        draw_test_menu(language);
        key = getch();
        if (key == 'q' || key == 'Q') {
            (void)snprintf(message, message_size,
                           language == FP_UI_LANGUAGE_ZH ? "已返回主界面。" :
                                                           "Returned to main screen.");
            break;
        }
        if (key == '1') {
            run_selected_test(language, FP_TEST_MODE_CONNECTIVITY, message, message_size);
        } else if (key == '2') {
            run_selected_test(language, FP_TEST_MODE_LATENCY, message, message_size);
        } else if (key == '3') {
            run_selected_test(language, FP_TEST_MODE_SPEED, message, message_size);
        }
    }
    timeout(1000);
}

static void format_bytes(char *buffer, size_t buffer_size, uint64_t bytes) {
    if (bytes >= 1024ull * 1024ull * 1024ull) {
        (void)snprintf(buffer, buffer_size, "%.2f GiB",
                       (double)bytes / (1024.0 * 1024.0 * 1024.0));
    } else if (bytes >= 1024ull * 1024ull) {
        (void)snprintf(buffer, buffer_size, "%.2f MiB", (double)bytes / (1024.0 * 1024.0));
    } else if (bytes >= 1024ull) {
        (void)snprintf(buffer, buffer_size, "%.1f KiB", (double)bytes / 1024.0);
    } else {
        (void)snprintf(buffer, buffer_size, "%llu B", (unsigned long long)bytes);
    }
}

static void format_rate(char *buffer, size_t buffer_size, double mbps) {
    if (mbps < 0.0) {
        mbps = 0.0;
    }
    (void)snprintf(buffer, buffer_size, "%.2f Mbps", mbps);
}

static void format_duration(char *buffer, size_t buffer_size, uint64_t age_ms) {
    uint64_t seconds = age_ms / 1000ull;
    uint64_t minutes = seconds / 60ull;
    uint64_t hours = minutes / 60ull;

    if (hours > 0) {
        (void)snprintf(buffer, buffer_size, "%lluh%02llum", (unsigned long long)hours,
                       (unsigned long long)(minutes % 60ull));
    } else if (minutes > 0) {
        (void)snprintf(buffer, buffer_size, "%llum%02llus", (unsigned long long)minutes,
                       (unsigned long long)(seconds % 60ull));
    } else {
        (void)snprintf(buffer, buffer_size, "%llus", (unsigned long long)seconds);
    }
}

struct monitor_rate_state {
    uint64_t anchor_up;
    uint64_t anchor_down;
    struct timespec anchor_time;
    double up_mbps;
    double down_mbps;
    int has_anchor;
};

static double timespec_elapsed_ms(const struct timespec *start, const struct timespec *end) {
    return (double)(end->tv_sec - start->tv_sec) * 1000.0 +
           (double)(end->tv_nsec - start->tv_nsec) / 1000000.0;
}

/*
 * Instant 50ms deltas flicker to 0 between TCP bursts. Display rate over a ~1s
 * window so the value tracks throughput without jumping through zero.
 */
static void update_monitor_rates(struct monitor_rate_state *state, uint64_t total_up,
                                 uint64_t total_down, const struct timespec *now) {
    double elapsed_ms;

    if (!state->has_anchor) {
        state->anchor_up = total_up;
        state->anchor_down = total_down;
        state->anchor_time = *now;
        state->up_mbps = 0.0;
        state->down_mbps = 0.0;
        state->has_anchor = 1;
        return;
    }

    elapsed_ms = timespec_elapsed_ms(&state->anchor_time, now);
    if (elapsed_ms < 200.0) {
        return;
    }

    state->up_mbps = ((double)(total_up - state->anchor_up) * 8.0) / (elapsed_ms * 1000.0);
    state->down_mbps = ((double)(total_down - state->anchor_down) * 8.0) / (elapsed_ms * 1000.0);

    if (elapsed_ms >= 1000.0) {
        state->anchor_up = total_up;
        state->anchor_down = total_down;
        state->anchor_time = *now;
    }
}

static void draw_monitor_page(enum fp_ui_language language, const struct fp_stats_snapshot *snapshot,
                              double up_mbps, double down_mbps, int daemon_running,
                              const char *status_line, int testing) {
    const char *title = language == FP_UI_LANGUAGE_ZH ? "流量与连接监控" : "Traffic monitor";
    const char *hint = testing ?
                           (language == FP_UI_LANGUAGE_ZH ? "测试中…  按 q 取消" :
                                                           "Testing…  press q to cancel") :
                           (language == FP_UI_LANGUAGE_ZH ?
                                "1 连通性  2 延迟  3 测速  |  q 返回" :
                                "1 connectivity  2 latency  3 speed  |  q back");
    char up_rate[32];
    char down_rate[32];
    char total_up[32];
    char total_down[32];
    char uptime[32];
    int row = 8;
    int list_bottom = LINES - 3;
    size_t index;
    size_t shown = 0;

    if (status_line != NULL && status_line[0] != '\0') {
        list_bottom = LINES - 4;
    }

    format_rate(up_rate, sizeof(up_rate), up_mbps);
    format_rate(down_rate, sizeof(down_rate), down_mbps);
    format_bytes(total_up, sizeof(total_up), snapshot->available ? snapshot->total_up : 0);
    format_bytes(total_down, sizeof(total_down), snapshot->available ? snapshot->total_down : 0);
    format_duration(uptime, sizeof(uptime), snapshot->available ? snapshot->uptime_ms : 0);

    erase();
    attron(A_BOLD | A_UNDERLINE);
    mvprintw(1, 4, "%s", title);
    attroff(A_BOLD | A_UNDERLINE);
    mvhline(2, 2, '-', COLS - 4);

    if (!daemon_running || !snapshot->available) {
        mvprintw(4, 4, "%s",
                 language == FP_UI_LANGUAGE_ZH ?
                     "转发服务未运行，暂无流量统计。" :
                     "Forwarder is not running; no live stats.");
    } else {
        mvprintw(3, 4,
                 language == FP_UI_LANGUAGE_ZH ?
                     "实时   ↑  %s      ↓  %s" :
                     "Live    ↑  %s      ↓  %s",
                 up_rate, down_rate);
        mvprintw(4, 4,
                 language == FP_UI_LANGUAGE_ZH ?
                     "累计   ↑  %s      ↓  %s      运行 %s" :
                     "Total   ↑  %s      ↓  %s      up %s",
                 total_up, total_down, uptime);
        mvprintw(5, 4,
                 language == FP_UI_LANGUAGE_ZH ? "活跃连接：%zu" : "Active connections: %zu",
                 snapshot->conn_count);
        mvhline(6, 2, '-', COLS - 4);
        mvprintw(7, 4,
                 language == FP_UI_LANGUAGE_ZH ?
                     "目标                      ↑  流量      ↓  流量     时长" :
                     "Destination               ↑  bytes     ↓  bytes    age");
        for (index = 0; index < snapshot->conn_count && row < list_bottom; ++index) {
            const struct fp_stats_conn_view *conn = &snapshot->connections[index];
            char address[INET_ADDRSTRLEN];
            char dest[32];
            char up_bytes[24];
            char down_bytes[24];
            char age[16];

            if (inet_ntop(AF_INET, &conn->dest_addr, address, sizeof(address)) == NULL) {
                continue;
            }
            (void)snprintf(dest, sizeof(dest), "%s:%u", address, conn->dest_port);
            format_bytes(up_bytes, sizeof(up_bytes), conn->bytes_up);
            format_bytes(down_bytes, sizeof(down_bytes), conn->bytes_down);
            format_duration(age, sizeof(age), conn->age_ms);
            mvprintw(row++, 4, "%-24s %10s %10s %7s", dest, up_bytes, down_bytes, age);
            ++shown;
        }
        if (shown == 0) {
            mvprintw(row, 4, "%s",
                     language == FP_UI_LANGUAGE_ZH ? "当前没有活跃连接。" :
                                                     "No active connections.");
        }
    }

    if (status_line != NULL && status_line[0] != '\0') {
        attron(A_BOLD);
        mvprintw(LINES - 3, 4, "%.*s", COLS - 8, status_line);
        attroff(A_BOLD);
    }
    attron(A_BOLD);
    mvprintw(LINES - 2, 4, "%s", hint);
    attroff(A_BOLD);
    refresh();
}

static void format_monitor_test_result(enum fp_ui_language language, enum fp_test_mode mode,
                                       const struct fp_test_report *report, char *message,
                                       size_t message_size) {
    if (!report->listener_ok) {
        (void)snprintf(message, message_size,
                       language == FP_UI_LANGUAGE_ZH ?
                           "测试失败：请确认服务、规则和宿主机 SOCKS5 可用。" :
                           "Test failed: check the forwarder, rules, and host SOCKS5.");
    } else if (report->cancelled) {
        (void)snprintf(message, message_size,
                       language == FP_UI_LANGUAGE_ZH ? "测试已取消。" : "Test cancelled.");
    } else if (mode == FP_TEST_MODE_SPEED) {
        (void)snprintf(message, message_size,
                       language == FP_UI_LANGUAGE_ZH ?
                           "测速结果：%zu/%zu，峰值 %.2f Mbps。" :
                           "Speed result: %zu/%zu, peak %.2f Mbps.",
                       report->speed_passed, report->speed_count, report->best_speed_mbps);
    } else if (mode == FP_TEST_MODE_LATENCY) {
        (void)snprintf(message, message_size,
                       language == FP_UI_LANGUAGE_ZH ? "延迟结果：%zu/%zu 成功。" :
                                                       "Latency result: %zu/%zu passed.",
                       report->sites_passed, report->site_count);
    } else {
        (void)snprintf(message, message_size,
                       language == FP_UI_LANGUAGE_ZH ? "连通性结果：%zu/%zu 成功。" :
                                                       "Connectivity result: %zu/%zu passed.",
                       report->sites_passed, report->site_count);
    }
}

static void run_monitor_test(enum fp_ui_language language, enum fp_test_mode mode,
                             char *status_line, size_t status_size,
                             struct monitor_rate_state *rates) {
    struct fp_test_report report;
    struct fp_test_progress_event event;
    struct test_worker_args args;
    struct fp_stats_snapshot snapshot;
    struct fp_status status;
    pthread_t worker;
    volatile sig_atomic_t cancel_flag = 0;
    int pipe_fds[2];
    int cancelling = 0;
    int finished = 0;

    memset(&report, 0, sizeof(report));
    memset(&event, 0, sizeof(event));
    if (pipe(pipe_fds) != 0) {
        (void)snprintf(status_line, status_size,
                       language == FP_UI_LANGUAGE_ZH ? "无法启动测试。" : "Unable to start test.");
        return;
    }

    args.mode = mode;
    args.report = &report;
    args.event_fd = pipe_fds[1];
    args.cancel_flag = &cancel_flag;
    if (pthread_create(&worker, NULL, test_worker_main, &args) != 0) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        (void)snprintf(status_line, status_size,
                       language == FP_UI_LANGUAGE_ZH ? "无法启动测试。" : "Unable to start test.");
        return;
    }

    (void)snprintf(status_line, status_size,
                   language == FP_UI_LANGUAGE_ZH ? "正在测试…" : "Testing…");
    nodelay(stdscr, TRUE);
    while (!finished) {
        struct pollfd descriptors[1] = {{.fd = pipe_fds[0], .events = POLLIN}};
        struct timespec now;
        int key = getch();
        int poll_result;

        if ((key == 'q' || key == 'Q') && !cancelling) {
            cancel_flag = 1;
            cancelling = 1;
            (void)snprintf(status_line, status_size,
                           language == FP_UI_LANGUAGE_ZH ? "正在取消测试…" : "Cancelling test…");
        }

        fp_collect_status(&status);
        fp_stats_reopen_readonly();
        memset(&snapshot, 0, sizeof(snapshot));
        if (status.daemon_running) {
            (void)fp_stats_snapshot(&snapshot);
        }
        (void)clock_gettime(CLOCK_MONOTONIC, &now);
        if (snapshot.available) {
            update_monitor_rates(rates, snapshot.total_up, snapshot.total_down, &now);
        }

        poll_result = poll(descriptors, 1, 50);
        if (poll_result > 0 && (descriptors[0].revents & POLLIN) != 0) {
            if (read_test_event(pipe_fds[0], &event) == 0) {
                if (event.phase == FP_TEST_PHASE_DONE) {
                    finished = 1;
                } else if (event.phase == FP_TEST_PHASE_SPEED &&
                           event.state == FP_TEST_SITE_RUNNING && event.speed_mbps > 0.0) {
                    (void)snprintf(status_line, status_size,
                                   language == FP_UI_LANGUAGE_ZH ?
                                       "测速中 %zu/%zu：%s  %.2f Mbps" :
                                       "Speed %zu/%zu: %s  %.2f Mbps",
                                   event.index, event.total, event.name, event.speed_mbps);
                } else if (event.name[0] != '\0' && event.phase != FP_TEST_PHASE_PREFLIGHT) {
                    (void)snprintf(status_line, status_size,
                                   language == FP_UI_LANGUAGE_ZH ? "测试中 %zu/%zu：%s" :
                                                                   "Testing %zu/%zu: %s",
                                   event.index, event.total, event.name);
                }
            } else {
                finished = 1;
            }
        } else if (poll_result < 0 && errno != EINTR) {
            finished = 1;
        }

        draw_monitor_page(language, &snapshot, rates->up_mbps, rates->down_mbps,
                          status.daemon_running, status_line, 1);
    }
    nodelay(stdscr, FALSE);
    (void)pthread_join(worker, NULL);
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    format_monitor_test_result(language, mode, &report, status_line, status_size);
}

static void run_monitor_page(enum fp_ui_language language, char *message, size_t message_size) {
    struct fp_stats_snapshot snapshot;
    struct fp_status status;
    struct monitor_rate_state rates;
    char status_line[160] = "";

    memset(&rates, 0, sizeof(rates));
    /*
     * Do not rely on timeout()+blocking getch() for idle refresh: on some terminals
     * it never wakes until a key is pressed, so the page looks frozen until a test
     * (which uses nodelay + poll) starts the update loop.
     */
    timeout(-1);
    nodelay(stdscr, TRUE);
    for (;;) {
        int key;
        struct timespec now;

        fp_collect_status(&status);
        fp_stats_reopen_readonly();
        memset(&snapshot, 0, sizeof(snapshot));
        if (status.daemon_running) {
            (void)fp_stats_snapshot(&snapshot);
        }
        (void)clock_gettime(CLOCK_MONOTONIC, &now);
        if (snapshot.available) {
            update_monitor_rates(&rates, snapshot.total_up, snapshot.total_down, &now);
        } else {
            memset(&rates, 0, sizeof(rates));
        }
        draw_monitor_page(language, &snapshot, rates.up_mbps, rates.down_mbps, status.daemon_running,
                          status_line, 0);

        key = getch();
        if (key == 'q' || key == 'Q') {
            (void)snprintf(message, message_size,
                           language == FP_UI_LANGUAGE_ZH ? "已返回主界面。" :
                                                           "Returned to main screen.");
            break;
        }
        if (key == '1') {
            nodelay(stdscr, FALSE);
            run_monitor_test(language, FP_TEST_MODE_CONNECTIVITY, status_line, sizeof(status_line),
                             &rates);
            nodelay(stdscr, TRUE);
        } else if (key == '2') {
            nodelay(stdscr, FALSE);
            run_monitor_test(language, FP_TEST_MODE_LATENCY, status_line, sizeof(status_line),
                             &rates);
            nodelay(stdscr, TRUE);
        } else if (key == '3') {
            nodelay(stdscr, FALSE);
            run_monitor_test(language, FP_TEST_MODE_SPEED, status_line, sizeof(status_line),
                             &rates);
            nodelay(stdscr, TRUE);
        } else {
            napms(200);
        }
    }
    nodelay(stdscr, FALSE);
    fp_stats_close();
    timeout(1000);
}

static int keypad_digit(int key) {
    switch (key) {
        case KEY_IC:
            return '0';
        case KEY_C1:
        case KEY_END:
            return '1';
        case KEY_DOWN:
            return '2';
        case KEY_C3:
        case KEY_NPAGE:
            return '3';
        case KEY_LEFT:
            return '4';
        case KEY_B2:
            return '5';
        case KEY_RIGHT:
            return '6';
        case KEY_A1:
        case KEY_HOME:
            return '7';
        case KEY_UP:
            return '8';
        case KEY_A3:
        case KEY_PPAGE:
            return '9';
        case KEY_DC:
            return '.';
        default:
            return key;
    }
}

static int read_proxy_key(void) {
    int key = getch();

    if (key != 27) {
        return key;
    }
    timeout(30);
    {
        int prefix = getch();
        int code = prefix == ERR ? ERR : getch();

        timeout(-1);
        if (prefix == 'O') {
            if (code >= 'p' && code <= 'y') {
                return '0' + code - 'p';
            }
            if (code == 'n') {
                return '.';
            }
        }
    }
    return 27;
}

static int prompt_proxy(char *proxy, size_t proxy_size, const struct ui_text *text) {
    int input_row = LINES - 4;
    int input_column;
    size_t length = 0;

    move(input_row, 2);
    clrtoeol();
    attron(A_BOLD);
    mvprintw(input_row, 4, "%s", text->prompt);
    attroff(A_BOLD);
    getyx(stdscr, input_row, input_column);
    proxy[0] = '\0';
    curs_set(1);
    keypad(stdscr, FALSE);
    timeout(-1);
    for (;;) {
        int key = read_proxy_key();

        if (key == 27 || key == 'q' || key == 'Q') {
            keypad(stdscr, TRUE);
            curs_set(0);
            timeout(1000);
            return -1;
        }
        if (key == '\n' || key == '\r' || key == KEY_ENTER) {
            break;
        }
        key = keypad_digit(key);
        if (key == KEY_BACKSPACE || key == 127 || key == '\b') {
            if (length > 0) {
                proxy[--length] = '\0';
            }
        } else if ((key == ':' || key == '.') || (key >= '0' && key <= '9')) {
            if (length + 1 < proxy_size) {
                proxy[length++] = (char)key;
                proxy[length] = '\0';
            }
        }
        mvprintw(input_row, input_column, "%s ", proxy);
        move(input_row, input_column + (int)length);
        refresh();
    }
    keypad(stdscr, TRUE);
    curs_set(0);
    timeout(1000);
    return 0;
}

static int confirm_uninstall(enum fp_ui_language language) {
    char answer[8] = "";
    int row = LINES - 4;

    move(row, 2);
    clrtoeol();
    mvprintw(row, 4, "%s",
             language == FP_UI_LANGUAGE_ZH ?
                 "确认卸载？这会停止服务、删除规则和配置。输入 yes：" :
                 "Confirm uninstall? Service, rules, and configuration will be removed. Type yes: ");
    echo();
    curs_set(1);
    timeout(-1);
    if (getnstr(answer, (int)sizeof(answer) - 1) == ERR) {
        answer[0] = '\0';
    }
    noecho();
    curs_set(0);
    timeout(1000);
    return strcmp(answer, "yes") == 0;
}

int fp_tui_run(void) {
    struct fp_status status;
    enum fp_ui_language language = fp_ui_language_load();
    const struct ui_text *text = &UI_TEXT[language];
    char message[128];
    int key;

    (void)setlocale(LC_ALL, "");
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    timeout(1000);
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_GREEN, -1);
        init_pair(2, COLOR_RED, -1);
    }
    (void)snprintf(message, sizeof(message), "%s", text->initial_message);

    for (;;) {
        fp_collect_status(&status);
        draw_screen(&status, text, message);
        key = getch();
        if (key == 'q' || key == 'Q') {
            break;
        }
        if (key == 's' || key == 'S') {
            if (fp_enable_saved_proxy() == 0) {
                (void)snprintf(message, sizeof(message),
                               language == FP_UI_LANGUAGE_ZH ? "已启用保存的代理配置。" :
                                                               "Saved proxy configuration enabled.");
            } else {
                (void)snprintf(message, sizeof(message), "%s", text->enable_failed);
            }
        } else if (key == 'e' || key == 'E') {
            char proxy[64] = "";

            if (prompt_proxy(proxy, sizeof(proxy), text) != 0) {
                (void)snprintf(message, sizeof(message), "%s", text->input_cancelled);
            } else if (fp_enable_proxy(proxy) == 0) {
                (void)snprintf(message, sizeof(message),
                               language == FP_UI_LANGUAGE_ZH ? "代理已启用：%s。" :
                                                               "Proxy enabled through %s.",
                               proxy);
            } else {
                (void)snprintf(message, sizeof(message), "%s", text->enable_failed);
            }
        } else if (key == 'd' || key == 'D') {
            if (fp_disable_proxy() == 0) {
                (void)snprintf(message, sizeof(message),
                               language == FP_UI_LANGUAGE_ZH ? "代理已停用。" : "Proxy disabled.");
            } else {
                (void)snprintf(message, sizeof(message), "%s", text->disable_failed);
            }
        } else if (key == 'a' || key == 'A') {
            if (status.autostart_enabled ? fp_autostart_disable() == 0 :
                                           fp_autostart_enable() == 0) {
                (void)snprintf(message, sizeof(message),
                               language == FP_UI_LANGUAGE_ZH ? "开机自启已%s。" :
                                                               "Boot startup %s.",
                               status.autostart_enabled ?
                                   (language == FP_UI_LANGUAGE_ZH ? "停用" : "disabled") :
                                   (language == FP_UI_LANGUAGE_ZH ? "启用" : "enabled"));
            } else {
                (void)snprintf(message, sizeof(message), "%s", text->startup_failed);
            }
        } else if (key == 'm' || key == 'M') {
            run_monitor_page(language, message, sizeof(message));
        } else if (key == 't' || key == 'T') {
            run_test_page(language, message, sizeof(message));
        } else if (key == 'u' || key == 'U') {
            if (!confirm_uninstall(language)) {
                (void)snprintf(message, sizeof(message),
                               language == FP_UI_LANGUAGE_ZH ? "已取消卸载。" :
                                                               "Uninstall cancelled.");
            } else if (fp_uninstall() == 0) {
                break;
            } else {
                (void)snprintf(message, sizeof(message),
                               language == FP_UI_LANGUAGE_ZH ? "卸载未能完整完成。" :
                                                               "Uninstall was incomplete.");
            }
        } else if (key == 'l' || key == 'L') {
            enum fp_ui_language next =
                language == FP_UI_LANGUAGE_ZH ? FP_UI_LANGUAGE_EN : FP_UI_LANGUAGE_ZH;

            if (fp_ui_language_save(next) == 0) {
                language = next;
                text = &UI_TEXT[language];
                (void)snprintf(message, sizeof(message),
                               language == FP_UI_LANGUAGE_ZH ? "界面语言已切换为中文。" :
                                                               "Interface language switched to English.");
            } else {
                (void)snprintf(message, sizeof(message), "%s", text->language_failed);
            }
        } else if (key == KEY_RESIZE || key == 'r' || key == 'R' || key == ERR) {
            continue;
        }
    }
    endwin();
    return 0;
}
