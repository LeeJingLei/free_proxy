#include "free_proxy.h"

#include <locale.h>
#include <ncursesw/ncurses.h>
#include <stdio.h>
#include <string.h>

#define MIN_ROWS 22
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
         "t  测试代理连接",
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
         "t  Test proxy connection",
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
    mvprintw(14, 4, "%s", text->test);
    mvprintw(15, 4, "%s", text->uninstall);
    mvprintw(16, 4, "%s", text->language);
    mvprintw(17, 4, "%s", text->refresh);
    mvprintw(18, 4, "%s", text->quit);
    mvprintw(19, 4, "%s", text->coverage);

    if (message[0] != '\0') {
        attron(A_BOLD);
        mvprintw(LINES - 2, 4, "%.*s", COLS - 8, message);
        attroff(A_BOLD);
    }
    refresh();
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
        } else if (key == 't' || key == 'T') {
            (void)snprintf(message, sizeof(message),
                           language == FP_UI_LANGUAGE_ZH ? "正在测试代理连接，请稍候…" :
                                                           "Testing proxy connection…");
            draw_screen(&status, text, message);
            if (fp_test_proxy() == 0) {
                (void)snprintf(message, sizeof(message),
                               language == FP_UI_LANGUAGE_ZH ?
                                   "测试通过：SOCKS5 已成功连接到 1.1.1.1:443。" :
                                   "Test passed: SOCKS5 connected to 1.1.1.1:443.");
            } else {
                (void)snprintf(message, sizeof(message),
                               language == FP_UI_LANGUAGE_ZH ?
                                   "测试失败：请确认服务、规则和宿主机 SOCKS5 可用。" :
                                   "Test failed: check the forwarder, rules, and host SOCKS5.");
            }
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
