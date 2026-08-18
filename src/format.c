#include "free_proxy.h"

#include <stdio.h>

static void format_scaled(char *buffer, size_t buffer_size, double value, const char *unit) {
    if (value >= 100.0 || value == (double)(uint64_t)value) {
        (void)snprintf(buffer, buffer_size, "%.0f %s", value, unit);
    } else if (value >= 10.0) {
        (void)snprintf(buffer, buffer_size, "%.1f %s", value, unit);
    } else {
        (void)snprintf(buffer, buffer_size, "%.2f %s", value, unit);
    }
}

void fp_format_bytes(char *buffer, size_t buffer_size, uint64_t bytes) {
    if (buffer == NULL || buffer_size == 0) {
        return;
    }
    if (bytes >= 1024ull * 1024ull * 1024ull) {
        format_scaled(buffer, buffer_size, (double)bytes / (1024.0 * 1024.0 * 1024.0), "GB");
    } else if (bytes >= 1024ull * 1024ull) {
        format_scaled(buffer, buffer_size, (double)bytes / (1024.0 * 1024.0), "MB");
    } else if (bytes >= 1024ull) {
        format_scaled(buffer, buffer_size, (double)bytes / 1024.0, "KB");
    } else {
        (void)snprintf(buffer, buffer_size, "%llu B", (unsigned long long)bytes);
    }
}

void fp_format_rate(char *buffer, size_t buffer_size, double bytes_per_sec) {
    if (buffer == NULL || buffer_size == 0) {
        return;
    }
    if (bytes_per_sec < 0.0) {
        bytes_per_sec = 0.0;
    }
    if (bytes_per_sec >= 1024.0 * 1024.0 * 1024.0) {
        format_scaled(buffer, buffer_size, bytes_per_sec / (1024.0 * 1024.0 * 1024.0), "GB/s");
    } else if (bytes_per_sec >= 1024.0 * 1024.0) {
        format_scaled(buffer, buffer_size, bytes_per_sec / (1024.0 * 1024.0), "MB/s");
    } else if (bytes_per_sec >= 1024.0) {
        format_scaled(buffer, buffer_size, bytes_per_sec / 1024.0, "KB/s");
    } else {
        (void)snprintf(buffer, buffer_size, "%.0f B/s", bytes_per_sec);
    }
}
