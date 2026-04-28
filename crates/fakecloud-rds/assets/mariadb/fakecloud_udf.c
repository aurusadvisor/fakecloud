/*
 * fakecloud_udf - tiny MySQL UDF that POSTs JSON to a fakecloud bridge
 * endpoint and returns the response body. Loaded by the prebuilt
 * fakecloud-mysql image so that Aurora-compatible stored procedures
 * (mysql.lambda_sync, mysql.lambda_async) can call into fakecloud
 * Lambda from inside the DB container.
 *
 * Two functions are exported:
 *
 *   fakecloud_post(url TEXT, body TEXT, timeout_ms INT) RETURNS TEXT
 *     Synchronous POST. Returns the response body (or "" on network
 *     failure). NULL inputs are treated as empty strings / 5000 ms.
 *
 *   fakecloud_post_async(url TEXT, body TEXT) RETURNS INT
 *     Spawns a detached worker that performs the POST in the background
 *     and returns 0 immediately. Used by `mysql.lambda_async`. The
 *     response is discarded.
 *
 * Build:   gcc -O2 -fPIC -shared -o fakecloud_udf.so fakecloud_udf.c -lcurl -lpthread
 * Install: copy the .so into the MySQL plugin dir (`SHOW VARIABLES LIKE
 *          'plugin_dir'`) and `CREATE FUNCTION`.
 */

#include <mysql.h>
#include <curl/curl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* ── shared helpers ─────────────────────────────────────────────────── */

struct curl_buf {
    char *data;
    size_t len;
};

static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    struct curl_buf *buf = (struct curl_buf *)userdata;
    char *grown = (char *)realloc(buf->data, buf->len + total + 1);
    if (!grown) return 0;
    buf->data = grown;
    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

static char *do_post(const char *url, const char *body, long timeout_ms,
                     size_t *out_len) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    struct curl_buf buf = { NULL, 0 };
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)(body ? strlen(body) : 0));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK) {
        free(buf.data);
        if (out_len) *out_len = 0;
        return NULL;
    }
    if (out_len) *out_len = buf.len;
    return buf.data;
}

/* ── fakecloud_post ─────────────────────────────────────────────────── */

bool fakecloud_post_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count < 2 || args->arg_count > 3) {
        strcpy(message, "fakecloud_post(url, body[, timeout_ms])");
        return 1;
    }
    args->arg_type[0] = STRING_RESULT;
    args->arg_type[1] = STRING_RESULT;
    if (args->arg_count == 3) args->arg_type[2] = INT_RESULT;
    initid->maybe_null = 1;
    initid->ptr = NULL;
    return 0;
}

void fakecloud_post_deinit(UDF_INIT *initid) {
    free(initid->ptr);
}

char *fakecloud_post(UDF_INIT *initid, UDF_ARGS *args, char *result,
                     unsigned long *length, char *is_null, char *error) {
    const char *url = args->args[0];
    const char *body = args->args[1];
    long timeout_ms = 5000;
    if (args->arg_count == 3 && args->args[2])
        timeout_ms = *((long long *)args->args[2]);
    if (!url) {
        *is_null = 1;
        return NULL;
    }
    size_t len = 0;
    char *resp = do_post(url, body, timeout_ms, &len);
    if (!resp) {
        *is_null = 1;
        return NULL;
    }
    initid->ptr = resp;
    *length = (unsigned long)len;
    return resp;
}

/* ── fakecloud_post_async ───────────────────────────────────────────── */

struct async_args {
    char *url;
    char *body;
};

static void *async_worker(void *p) {
    struct async_args *a = (struct async_args *)p;
    char *resp = do_post(a->url, a->body, 30000, NULL);
    free(resp);
    free(a->url);
    free(a->body);
    free(a);
    return NULL;
}

bool fakecloud_post_async_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count != 2) {
        strcpy(message, "fakecloud_post_async(url, body)");
        return 1;
    }
    args->arg_type[0] = STRING_RESULT;
    args->arg_type[1] = STRING_RESULT;
    initid->maybe_null = 0;
    return 0;
}

void fakecloud_post_async_deinit(UDF_INIT *initid) {
    (void)initid;
}

long long fakecloud_post_async(UDF_INIT *initid, UDF_ARGS *args, char *is_null,
                               char *error) {
    (void)initid; (void)is_null; (void)error;
    if (!args->args[0]) return -1;
    struct async_args *a = (struct async_args *)malloc(sizeof(*a));
    if (!a) return -1;
    a->url = strdup(args->args[0]);
    a->body = args->args[1] ? strdup(args->args[1]) : strdup("");
    if (!a->url || !a->body) {
        free(a->url); free(a->body); free(a);
        return -1;
    }
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&tid, &attr, async_worker, a);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        free(a->url); free(a->body); free(a);
        return -1;
    }
    return 0;
}
