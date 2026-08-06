#include "free_proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define FP_STATS_MAGIC 0x46505354u
#define FP_STATS_VERSION 1u

struct fp_stats_conn {
    volatile uint32_t active;
    uint32_t dest_addr;
    uint16_t dest_port;
    uint16_t pad;
    int32_t pid;
    uint64_t bytes_up;
    uint64_t bytes_down;
    uint64_t start_ms;
};

struct fp_stats_map {
    uint32_t magic;
    uint32_t version;
    uint32_t slot_count;
    uint32_t pad;
    uint64_t started_ms;
    volatile uint64_t total_up;
    volatile uint64_t total_down;
    struct fp_stats_conn slots[FP_MAX_CLIENTS];
};

static struct fp_stats_map *stats_map = NULL;
static int stats_fd = -1;
static int stats_owner = 0;

static uint64_t monotonic_ms(void) {
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        return 0;
    }
    return (uint64_t)value.tv_sec * 1000ull + (uint64_t)value.tv_nsec / 1000000ull;
}

static int map_stats(int file_descriptor, int writable) {
    void *mapped = mmap(NULL, sizeof(struct fp_stats_map),
                        writable ? (PROT_READ | PROT_WRITE) : PROT_READ, MAP_SHARED,
                        file_descriptor, 0);
    if (mapped == MAP_FAILED) {
        return -1;
    }
    stats_map = mapped;
    stats_fd = file_descriptor;
    return 0;
}

int fp_stats_create(void) {
    int file_descriptor;

    if (stats_map != NULL) {
        return 0;
    }
    if (mkdir(FP_RUNTIME_DIR, 0755) == -1 && errno != EEXIST) {
        return -1;
    }
    (void)unlink(FP_STATS_PATH);
    file_descriptor = open(FP_STATS_PATH, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (file_descriptor < 0) {
        return -1;
    }
    if (ftruncate(file_descriptor, (off_t)sizeof(struct fp_stats_map)) != 0) {
        close(file_descriptor);
        (void)unlink(FP_STATS_PATH);
        return -1;
    }
    if (map_stats(file_descriptor, 1) != 0) {
        close(file_descriptor);
        (void)unlink(FP_STATS_PATH);
        return -1;
    }
    memset(stats_map, 0, sizeof(*stats_map));
    stats_map->magic = FP_STATS_MAGIC;
    stats_map->version = FP_STATS_VERSION;
    stats_map->slot_count = FP_MAX_CLIENTS;
    stats_map->started_ms = monotonic_ms();
    /*
     * Worker processes drop privileges to nobody (65534). Shared file mappings
     * re-check write permission on page faults, so the stats file must be owned
     * by that user or workers silently fail to update counters.
     */
    if (fchown(file_descriptor, 65534, 65534) != 0) {
        /* Fall back to world-writable so counters still work in restricted environments. */
        (void)fchmod(file_descriptor, 0666);
    }
    stats_owner = 1;
    return 0;
}

int fp_stats_open_readonly(void) {
    int file_descriptor;

    if (stats_map != NULL) {
        return 0;
    }
    file_descriptor = open(FP_STATS_PATH, O_RDONLY | O_CLOEXEC);
    if (file_descriptor < 0) {
        return -1;
    }
    if (map_stats(file_descriptor, 0) != 0) {
        close(file_descriptor);
        return -1;
    }
    if (stats_map->magic != FP_STATS_MAGIC || stats_map->version != FP_STATS_VERSION ||
        stats_map->slot_count > FP_MAX_CLIENTS) {
        munmap(stats_map, sizeof(struct fp_stats_map));
        stats_map = NULL;
        close(file_descriptor);
        stats_fd = -1;
        return -1;
    }
    stats_owner = 0;
    return 0;
}

void fp_stats_close(void) {
    if (stats_map != NULL) {
        munmap(stats_map, sizeof(struct fp_stats_map));
        stats_map = NULL;
    }
    if (stats_fd >= 0) {
        close(stats_fd);
        stats_fd = -1;
    }
    if (stats_owner) {
        (void)unlink(FP_STATS_PATH);
        stats_owner = 0;
    }
}

void fp_stats_reopen_readonly(void) {
    struct stat info;

    if (stats_owner) {
        return;
    }
    if (stats_map != NULL && stats_fd >= 0 && fstat(stats_fd, &info) == 0 && info.st_nlink > 0 &&
        stats_map->magic == FP_STATS_MAGIC && stats_map->version == FP_STATS_VERSION) {
        return;
    }
    if (stats_map != NULL) {
        munmap(stats_map, sizeof(struct fp_stats_map));
        stats_map = NULL;
    }
    if (stats_fd >= 0) {
        close(stats_fd);
        stats_fd = -1;
    }
    (void)fp_stats_open_readonly();
}

void fp_stats_unlink(void) {
    (void)unlink(FP_STATS_PATH);
}

int fp_stats_claim(const struct sockaddr_in *destination) {
    size_t index;

    if (stats_map == NULL || destination == NULL) {
        return -1;
    }
    for (index = 0; index < stats_map->slot_count && index < FP_MAX_CLIENTS; ++index) {
        struct fp_stats_conn *slot = &stats_map->slots[index];

        if (__sync_bool_compare_and_swap(&slot->active, 0u, 1u)) {
            slot->dest_addr = destination->sin_addr.s_addr;
            slot->dest_port = ntohs(destination->sin_port);
            slot->pid = (int32_t)getpid();
            slot->bytes_up = 0;
            slot->bytes_down = 0;
            slot->start_ms = monotonic_ms();
            return (int)index;
        }
    }
    return -1;
}

void fp_stats_add(int slot_index, uint64_t bytes_up, uint64_t bytes_down) {
    struct fp_stats_conn *slot;

    if (stats_map == NULL || slot_index < 0 || (size_t)slot_index >= stats_map->slot_count) {
        return;
    }
    slot = &stats_map->slots[slot_index];
    if (slot->active == 0 || slot->pid != (int32_t)getpid()) {
        return;
    }
    if (bytes_up > 0) {
        slot->bytes_up += bytes_up;
        __sync_fetch_and_add(&stats_map->total_up, bytes_up);
    }
    if (bytes_down > 0) {
        slot->bytes_down += bytes_down;
        __sync_fetch_and_add(&stats_map->total_down, bytes_down);
    }
}

void fp_stats_release(int slot_index) {
    struct fp_stats_conn *slot;

    if (stats_map == NULL || slot_index < 0 || (size_t)slot_index >= stats_map->slot_count) {
        return;
    }
    slot = &stats_map->slots[slot_index];
    if (slot->pid != (int32_t)getpid()) {
        return;
    }
    slot->bytes_up = 0;
    slot->bytes_down = 0;
    slot->dest_addr = 0;
    slot->dest_port = 0;
    slot->pid = 0;
    slot->start_ms = 0;
    __atomic_store_n(&slot->active, 0u, __ATOMIC_RELEASE);
}

void fp_stats_clear_pid(pid_t pid) {
    size_t index;

    if (stats_map == NULL || pid <= 1) {
        return;
    }
    for (index = 0; index < stats_map->slot_count && index < FP_MAX_CLIENTS; ++index) {
        struct fp_stats_conn *slot = &stats_map->slots[index];

        if (slot->active != 0 && slot->pid == (int32_t)pid) {
            slot->bytes_up = 0;
            slot->bytes_down = 0;
            slot->dest_addr = 0;
            slot->dest_port = 0;
            slot->pid = 0;
            slot->start_ms = 0;
            __atomic_store_n(&slot->active, 0u, __ATOMIC_RELEASE);
        }
    }
}

int fp_stats_snapshot(struct fp_stats_snapshot *snapshot) {
    size_t index;
    uint64_t now;

    if (snapshot == NULL) {
        return -1;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    if (stats_map == NULL && fp_stats_open_readonly() != 0) {
        return -1;
    }
    if (stats_map == NULL || stats_map->magic != FP_STATS_MAGIC ||
        stats_map->version != FP_STATS_VERSION) {
        return -1;
    }
    now = monotonic_ms();
    snapshot->available = true;
    snapshot->started_ms = stats_map->started_ms;
    snapshot->uptime_ms = now > stats_map->started_ms ? now - stats_map->started_ms : 0;
    snapshot->total_up = __atomic_load_n(&stats_map->total_up, __ATOMIC_RELAXED);
    snapshot->total_down = __atomic_load_n(&stats_map->total_down, __ATOMIC_RELAXED);
    for (index = 0; index < stats_map->slot_count && index < FP_MAX_CLIENTS; ++index) {
        const struct fp_stats_conn *slot = &stats_map->slots[index];
        struct fp_stats_conn_view *view;

        if (slot->active == 0 || slot->pid <= 1) {
            continue;
        }
        if (kill((pid_t)slot->pid, 0) != 0 && errno == ESRCH) {
            continue;
        }
        if (snapshot->conn_count >= FP_MAX_CLIENTS) {
            break;
        }
        view = &snapshot->connections[snapshot->conn_count++];
        view->dest_addr.s_addr = slot->dest_addr;
        view->dest_port = slot->dest_port;
        view->pid = (pid_t)slot->pid;
        view->bytes_up = slot->bytes_up;
        view->bytes_down = slot->bytes_down;
        view->age_ms = now > slot->start_ms ? now - slot->start_ms : 0;
    }
    return 0;
}
