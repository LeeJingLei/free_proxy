#include "free_proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int ensure_config_dir(void) {
    if (mkdir(FP_CONFIG_DIR, 0700) == -1 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

int fp_parse_proxy(const char *value, struct fp_config *config) {
    char address[INET_ADDRSTRLEN];
    const char *separator = strrchr(value, ':');
    char *end = NULL;
    long port;
    size_t address_length;

    if (separator == NULL || separator == value) {
        return -1;
    }
    address_length = (size_t)(separator - value);
    if (address_length >= sizeof(address)) {
        return -1;
    }
    memcpy(address, value, address_length);
    address[address_length] = '\0';
    errno = 0;
    port = strtol(separator + 1, &end, 10);
    if (errno != 0 || *end != '\0' || port < 1 || port > 65535 ||
        inet_pton(AF_INET, address, &config->proxy_addr) != 1) {
        return -1;
    }
    config->proxy_port = (unsigned short)port;
    return 0;
}

static int append_bypass(const char *value, size_t length, struct fp_config *config) {
    char token[INET_ADDRSTRLEN + 4];
    char address[INET_ADDRSTRLEN];
    char *slash;
    char *end = NULL;
    long prefix = 32;
    struct in_addr parsed;
    uint32_t host_address;
    uint32_t mask;
    size_t index;

    while (length > 0 && (*value == ' ' || *value == '\t')) {
        ++value;
        --length;
    }
    while (length > 0 && (value[length - 1] == ' ' || value[length - 1] == '\t')) {
        --length;
    }
    if (length == 0 || length >= sizeof(token) || config->bypass_count >= FP_MAX_BYPASS) {
        return -1;
    }
    memcpy(token, value, length);
    token[length] = '\0';
    slash = strchr(token, '/');
    if (slash != NULL) {
        *slash++ = '\0';
        errno = 0;
        prefix = strtol(slash, &end, 10);
        if (errno != 0 || *slash == '\0' || *end != '\0' || prefix < 0 || prefix > 32) {
            return -1;
        }
    }
    if (inet_pton(AF_INET, token, &parsed) != 1) {
        return -1;
    }
    host_address = ntohl(parsed.s_addr);
    mask = prefix == 0 ? 0 : UINT32_MAX << (32 - (unsigned int)prefix);
    parsed.s_addr = htonl(host_address & mask);
    for (index = 0; index < config->bypass_count; ++index) {
        if (config->bypass[index].network.s_addr == parsed.s_addr &&
            config->bypass[index].prefix == (unsigned char)prefix) {
            return 0;
        }
    }
    config->bypass[config->bypass_count].network = parsed;
    config->bypass[config->bypass_count].prefix = (unsigned char)prefix;
    if (inet_ntop(AF_INET, &parsed, address, sizeof(address)) == NULL ||
        (prefix == 32
             ? snprintf(config->bypass[config->bypass_count].text,
                        sizeof(config->bypass[config->bypass_count].text), "%s", address)
             : snprintf(config->bypass[config->bypass_count].text,
                        sizeof(config->bypass[config->bypass_count].text), "%s/%ld", address,
                        prefix)) < 0) {
        return -1;
    }
    ++config->bypass_count;
    return 0;
}

int fp_parse_bypass_list(const char *value, struct fp_config *config) {
    const char *start = value;
    const char *cursor = value;

    config->bypass_count = 0;
    if (value == NULL || *value == '\0') {
        return 0;
    }
    for (;;) {
        if (*cursor == ',' || *cursor == '\0') {
            if (append_bypass(start, (size_t)(cursor - start), config) != 0) {
                config->bypass_count = 0;
                return -1;
            }
            if (*cursor == '\0') {
                return 0;
            }
            start = cursor + 1;
        }
        ++cursor;
    }
}

bool fp_config_exists(void) {
    return access(FP_CONFIG_PATH, R_OK) == 0;
}

enum fp_ui_language fp_ui_language_load(void) {
    FILE *file = fopen(FP_UI_LANGUAGE_PATH, "r");
    char value[8];

    if (file == NULL) {
        return FP_UI_LANGUAGE_ZH;
    }
    if (fgets(value, sizeof(value), file) != NULL && strcmp(value, "en\n") == 0) {
        fclose(file);
        return FP_UI_LANGUAGE_EN;
    }
    fclose(file);
    return FP_UI_LANGUAGE_ZH;
}

int fp_ui_language_save(enum fp_ui_language language) {
    FILE *file;
    int result = 0;

    if (ensure_config_dir() != 0) {
        return -1;
    }
    file = fopen(FP_UI_LANGUAGE_PATH, "w");
    if (file == NULL) {
        return -1;
    }
    if (fputs(language == FP_UI_LANGUAGE_EN ? "en\n" : "zh\n", file) == EOF) {
        result = -1;
    }
    if (fclose(file) != 0) {
        result = -1;
    }
    return result;
}

int fp_config_save(const struct fp_config *config) {
    char address[INET_ADDRSTRLEN];
    char temporary_path[sizeof(FP_CONFIG_PATH) + 16];
    int file_descriptor;
    int length;
    int write_result = 0;

    if (ensure_config_dir() != 0) {
        return -1;
    }
    if (inet_ntop(AF_INET, &config->proxy_addr, address, sizeof(address)) == NULL) {
        return -1;
    }
    length = snprintf(temporary_path, sizeof(temporary_path), "%s.tmp.%ld",
                      FP_CONFIG_PATH, (long)getpid());
    if (length < 0 || (size_t)length >= sizeof(temporary_path)) {
        return -1;
    }
    file_descriptor = open(temporary_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (file_descriptor < 0) {
        return -1;
    }
    if (dprintf(file_descriptor, "proxy=%s:%u\n", address, config->proxy_port) < 0) {
        write_result = -1;
    }
    for (size_t index = 0; index < config->bypass_count; ++index) {
        if (dprintf(file_descriptor, "bypass=%s\n", config->bypass[index].text) < 0) {
            write_result = -1;
        }
    }
    if (fsync(file_descriptor) != 0) {
        write_result = -1;
    }
    if (close(file_descriptor) != 0) {
        write_result = -1;
    }
    if (write_result != 0) {
        unlink(temporary_path);
        return -1;
    }
    if (rename(temporary_path, FP_CONFIG_PATH) != 0) {
        unlink(temporary_path);
        return -1;
    }
    return 0;
}

int fp_config_load(struct fp_config *config) {
    FILE *file;
    char line[128];
    int result = -1;
    bool invalid = false;

    file = fopen(FP_CONFIG_PATH, "r");
    if (file == NULL) {
        return -1;
    }
    memset(config, 0, sizeof(*config));
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "proxy=", 6) == 0) {
            result = fp_parse_proxy(line + 6, config);
            if (result != 0) {
                invalid = true;
            }
        } else if (strncmp(line, "bypass=", 7) == 0 &&
                   append_bypass(line + 7, strlen(line + 7), config) != 0) {
            invalid = true;
        }
    }
    fclose(file);
    return result == 0 && !invalid ? 0 : -1;
}
