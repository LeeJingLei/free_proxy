#include "free_proxy.h"

#include <curl/curl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>

struct web_probe_progress {
    atomic_bool *cancel_flag;
};

static pthread_once_t curl_init_once = PTHREAD_ONCE_INIT;
static int curl_initialized;

static void initialize_curl(void) {
    curl_initialized = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
}

int fp_web_probe_init(void) {
    return pthread_once(&curl_init_once, initialize_curl) == 0 && curl_initialized ? 0 : -1;
}

static size_t discard_response(char *data, size_t size, size_t count, void *context) {
    (void)data;
    (void)context;
    return size * count;
}

static int probe_progress(void *context, curl_off_t download_total, curl_off_t download_now,
                          curl_off_t upload_total, curl_off_t upload_now) {
    const struct web_probe_progress *progress = context;

    (void)download_total;
    (void)download_now;
    (void)upload_total;
    (void)upload_now;
    return progress->cancel_flag != NULL &&
           atomic_load_explicit(progress->cancel_flag, memory_order_acquire);
}

int fp_web_probe(const char *domain, unsigned short port, int *latency_ms,
                 atomic_bool *cancel_flag) {
    struct web_probe_progress progress = {.cancel_flag = cancel_flag};
    char url[384];
    CURL *handle = NULL;
    CURLcode result = CURLE_FAILED_INIT;
    double first_byte_seconds = 0.0;
    long response_code = 0;
    int written;
    int status = -1;

    if (domain == NULL || domain[0] == '\0' || port == 0 || latency_ms == NULL ||
        fp_web_probe_init() != 0) {
        return -1;
    }
    if (cancel_flag != NULL &&
        atomic_load_explicit(cancel_flag, memory_order_acquire)) {
        return -2;
    }
    written = snprintf(url, sizeof(url), "%s://%s:%u/", port == 443 ? "https" : "http",
                       domain, port);
    if (written < 0 || (size_t)written >= sizeof(url)) {
        return -1;
    }
    handle = curl_easy_init();
    if (handle == NULL) {
        return -1;
    }

    if (curl_easy_setopt(handle, CURLOPT_URL, url) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_NOBODY, 1L) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, (long)FP_TEST_TIMEOUT_MS) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, (long)FP_TEST_TIMEOUT_MS) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_PROXY, "") != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_FRESH_CONNECT, 1L) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_FORBID_REUSE, 1L) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_DNS_CACHE_TIMEOUT, 0L) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_USERAGENT, "free_proxy/1.0") != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, discard_response) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_XFERINFOFUNCTION, probe_progress) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_XFERINFODATA, &progress) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_NOPROGRESS, 0L) != CURLE_OK) {
        goto done;
    }

    result = curl_easy_perform(handle);
    if (result == CURLE_ABORTED_BY_CALLBACK && cancel_flag != NULL &&
        atomic_load_explicit(cancel_flag, memory_order_acquire)) {
        status = -2;
        goto done;
    }
    if (result != CURLE_OK ||
        curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response_code) != CURLE_OK ||
        curl_easy_getinfo(handle, CURLINFO_STARTTRANSFER_TIME, &first_byte_seconds) != CURLE_OK ||
        response_code < 100 || response_code >= 600 || first_byte_seconds < 0.0 ||
        first_byte_seconds > (double)INT_MAX / 1000.0) {
        goto done;
    }
    *latency_ms = (int)(first_byte_seconds * 1000.0 + 0.5);
    status = 0;

done:
    curl_easy_cleanup(handle);
    return status;
}
