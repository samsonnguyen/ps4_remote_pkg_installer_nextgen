/*
 * Remote PKG Installer NextGen
 * Copyright (c) 2025-present AldySan and contributors.
 * Licensed under the GNU General Public License v3.0. See LICENSE for details.
 */
#include "prefetch.h"
#include "diag.h"
#include "http_client.h"
#include "log.h"

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* musl exports it; the header only declares it under _GNU_SOURCE. */
extern int pthread_getattr_np(pthread_t thread, pthread_attr_t* attr);

/*
 * Corruption probes. Two crashes on firmware 14.0 (__bin_chunk in free,
 * then a garbage stdout FILE in locking_putc) appeared only while several
 * multi-worker engines were alive. These probes record, in the boot
 * journal, which of the candidates it is:
 *  - a heap overrun: guard bytes after the ring, the chunk-state array and
 *    every worker buffer, plus magic words around each engine struct;
 *  - a stack overrun: each worker paints its stack and reports how deep
 *    it went, next to the platform default stack size.
 */
#define PF_CANARY_LEN   64
#define PF_CANARY_BYTE  0xA5
#define PF_MAGIC_HEAD   0x50464845414430ULL /* "PFHEAD0" */
#define PF_MAGIC_TAIL   0x50465441494C30ULL /* "PFTAIL0" */
#define PF_STACK_PAINT  0x5AF00D5Au

static void canary_set(uint8_t* p, size_t len)
{
    memset(p + len, PF_CANARY_BYTE, PF_CANARY_LEN);
}

static bool canary_ok(const uint8_t* p, size_t len)
{
    size_t i;
    for (i = 0; i < PF_CANARY_LEN; ++i) {
        if (p[len + i] != PF_CANARY_BYTE) {
            return false;
        }
    }
    return true;
}

static int s_canary_reports = 0;

static void canary_report(const char* what, const void* pf, size_t extra)
{
    /* One journal line per kind of failure is enough to name it. */
    if (__atomic_fetch_add(&s_canary_reports, 1, __ATOMIC_RELAXED) < 8) {
        diag_notef("probe-corrupt-%s-pf-%p-x-%zu", what, pf, extra);
        LOG_ERROR("prefetch: corruption detected: %s (engine %p, %zu)",
                  what, pf, extra);
    }
}

static size_t s_stack_hw_max = 0;

/* Paints the unused part of this thread's stack; returns its lowest
 * painted address (0 when the bounds are unknown). */
static uintptr_t stack_paint(void)
{
    pthread_attr_t attr;
    void* addr = NULL;
    size_t size = 0;
    volatile uint32_t* p;
    uintptr_t lo;
    uintptr_t sp = (uintptr_t)&attr;

    if (pthread_getattr_np(pthread_self(), &attr) != 0) {
        return 0;
    }
    pthread_attr_getstack(&attr, &addr, &size);
    pthread_attr_destroy(&attr);
    if (!addr || size < 64u * 1024u) {
        return 0;
    }
    lo = ((uintptr_t)addr + 4096u + 3u) & ~(uintptr_t)3u; /* skip a page */
    if (sp < lo + 8192u) {
        return 0;
    }
    for (p = (volatile uint32_t*)lo; (uintptr_t)p < sp - 2048u; ++p) {
        *p = PF_STACK_PAINT;
    }
    {
        static int s_bounds_noted = 0;
        if (__atomic_fetch_add(&s_bounds_noted, 1, __ATOMIC_RELAXED) == 0) {
            pthread_attr_t def;
            size_t def_size = 0;
            pthread_attr_init(&def);
            pthread_attr_getstacksize(&def, &def_size);
            pthread_attr_destroy(&def);
            diag_notef("probe-stack-worker-size-%zu-default-%zu", size, def_size);
        }
    }
    return lo;
}

/* Reports the deepest stack use since stack_paint (new maxima only). */
static void stack_report(uintptr_t lo)
{
    volatile uint32_t* p;
    uintptr_t top;
    pthread_attr_t attr;
    void* addr = NULL;
    size_t size = 0;
    size_t used;
    size_t prev;

    if (!lo || pthread_getattr_np(pthread_self(), &attr) != 0) {
        return;
    }
    pthread_attr_getstack(&attr, &addr, &size);
    pthread_attr_destroy(&attr);
    top = (uintptr_t)addr + size;
    for (p = (volatile uint32_t*)lo; (uintptr_t)p < top && *p == PF_STACK_PAINT; ++p) {
    }
    used = top - (uintptr_t)p;
    prev = __atomic_load_n(&s_stack_hw_max, __ATOMIC_RELAXED);
    if (used > prev) {
        __atomic_store_n(&s_stack_hw_max, used, __ATOMIC_RELAXED);
        diag_notef("probe-stack-hw-%zu-of-%zu%s", used, size,
                   ((uintptr_t)p <= lo) ? "-REACHED-GUARD" : "");
    }
}

/*
 * Design: all workers pull from a SHARED sequential chunk frontier.
 *
 * The resource is cut into fixed-size chunks (2 MiB). Each worker picks the
 * next unclaimed chunk nearest the consumer frontier (so N workers fetch N
 * consecutive chunks in parallel), fetches it with one HTTP Range request,
 * and stores it into the ring. The consumer reads strictly sequentially and
 * only ever waits for its next chunks. This gives a true N-times speedup
 * for sequential consumers (BGFT piece downloads) even when each connection
 * is throttled.
 */

#define PREFETCH_RING_BUDGET  (96u * 1024u * 1024u) /* shared by all streams */
#define PREFETCH_RING_TARGET  (32u * 1024u * 1024u) /* per-stream default */
#define PREFETCH_RING_MIN     (4u * 1024u * 1024u)
#define PREFETCH_CHUNK_SIZE   (2u * 1024u * 1024u)  /* per-request granularity */
#define PREFETCH_MAX_CONNS    8
#define PREFETCH_WORKER_STACK (512u * 1024u)

enum chunk_state {
    CHUNK_PENDING = 0,
    CHUNK_DONE = 1,
    CHUNK_FAILED = 2,
    CHUNK_CLAIMED = 3,
};

struct prefetch {
    uint64_t magic_head;         /* PF_MAGIC_HEAD while alive */
    char url[2048];
    uint64_t base;               /* origin offset of stream byte 0 */
    uint64_t total_size;         /* stream length from base */
    int connections;

    uint8_t* ring;
    size_t ring_size;

    pthread_mutex_t lock;
    pthread_cond_t data_avail;   /* a chunk completed (or abort/failure) */
    pthread_cond_t work_avail;   /* window advanced / chunks became claimable */

    bool aborting;

    uint8_t* chunk_state;
    size_t chunk_count;
    uint64_t filled_bytes;
    uint64_t consumed_bytes;     /* sequential consumer frontier */
    bool read_failed;

    pthread_t threads[PREFETCH_MAX_CONNS];
    int thread_count;
    bool threads_spawned;
    uint64_t magic_tail;         /* PF_MAGIC_TAIL while alive */
};

/* Checks the engine struct and its buffers; reports what is broken. */
static bool pf_intact(const prefetch_t* pf, const char* where)
{
    bool ok = true;
    if (pf->magic_head != PF_MAGIC_HEAD || pf->magic_tail != PF_MAGIC_TAIL) {
        canary_report(where, pf, 1);
        return false;
    }
    if (pf->ring && !canary_ok(pf->ring, pf->ring_size)) {
        canary_report(where, pf, 2);
        ok = false;
    }
    if (pf->chunk_state && !canary_ok(pf->chunk_state, pf->chunk_count)) {
        canary_report(where, pf, 3);
        ok = false;
    }
    return ok;
}

struct worker_ctx {
    prefetch_t* pf;
};

/* The heap is 256 MiB and BGFT downloads several tasks concurrently, so a
 * fixed 64 MiB ring per stream exhausted it and made valid pieces fail.
 * Every live stream now draws from a shared budget: the first stream gets
 * the full target, later ones share what is left, and the floor keeps the
 * engine usable instead of failing outright. */
static pthread_mutex_t s_ring_lock = PTHREAD_MUTEX_INITIALIZER;
static size_t s_ring_bytes = 0;
static int s_live_engines = 0;   /* started and not yet fully freed */

int prefetch_live_count(void)
{
    return __atomic_load_n(&s_live_engines, __ATOMIC_ACQUIRE);
}

static size_t ring_size_for(uint64_t total_size)
{
    size_t avail;
    size_t want;

    pthread_mutex_lock(&s_ring_lock);
    avail = (s_ring_bytes < PREFETCH_RING_BUDGET)
                ? PREFETCH_RING_BUDGET - s_ring_bytes
                : 0;
    pthread_mutex_unlock(&s_ring_lock);

    want = (avail > PREFETCH_RING_TARGET) ? PREFETCH_RING_TARGET : avail;
    if (want < PREFETCH_RING_MIN) {
        want = PREFETCH_RING_MIN;
    }
    if ((uint64_t)want > total_size) {
        want = (size_t)total_size;
    }
    /* Whole chunks only, so the worker window (ring / chunk) is never 0. */
    want = (want + PREFETCH_CHUNK_SIZE - 1) & ~(size_t)(PREFETCH_CHUNK_SIZE - 1);
    return want;
}

static void ring_budget_add(size_t bytes)
{
    pthread_mutex_lock(&s_ring_lock);
    s_ring_bytes += bytes;
    pthread_mutex_unlock(&s_ring_lock);
}

static void ring_budget_sub(size_t bytes)
{
    pthread_mutex_lock(&s_ring_lock);
    if (s_ring_bytes >= bytes) {
        s_ring_bytes -= bytes;
    } else {
        s_ring_bytes = 0;
    }
    pthread_mutex_unlock(&s_ring_lock);
}

static uint64_t chunk_start(size_t chunk)
{
    return (uint64_t)chunk * PREFETCH_CHUNK_SIZE;
}

static size_t chunk_index(uint64_t pos)
{
    return (size_t)(pos / PREFETCH_CHUNK_SIZE);
}

static void* worker_run(prefetch_t* pf);

static void* worker_thread(void* arg)
{
    struct worker_ctx* ctx = (struct worker_ctx*)arg;
    prefetch_t* pf = ctx->pf;
    uintptr_t painted;
    void* ret;

    free(ctx);
    painted = stack_paint();
    ret = worker_run(pf);
    stack_report(painted);
    return ret;
}

static void* worker_run(prefetch_t* pf)
{
    http_session_t* sess = NULL;
    uint8_t* buf = NULL;

    buf = (uint8_t*)malloc(PREFETCH_CHUNK_SIZE + PF_CANARY_LEN);
    if (buf) {
        canary_set(buf, PREFETCH_CHUNK_SIZE);
    }
    if (!buf) {
        pthread_mutex_lock(&pf->lock);
        pf->read_failed = true;
        pthread_cond_broadcast(&pf->data_avail);
        pthread_mutex_unlock(&pf->lock);
        return NULL;
    }

    for (;;) {
        size_t c = (size_t)-1;
        uint64_t off;
        size_t want;
        http_result_t r = { 0 }; /* read in the failure log even when the
                                  * session could not be opened (r unfilled) */
        bool aborting;
        bool fetched;

        /* Claim the next pending chunk inside the ring window. */
        pthread_mutex_lock(&pf->lock);
        for (;;) {
            size_t first = chunk_index(pf->consumed_bytes);
            size_t last = first + pf->ring_size / PREFETCH_CHUNK_SIZE; /* exclusive */
            size_t i;
            bool any_pending = false;

            if (pf->aborting) {
                pthread_mutex_unlock(&pf->lock);
                http_session_close(sess);
                free(buf);
                return NULL;
            }

            for (i = first; i < last && i < pf->chunk_count; ++i) {
                if (pf->chunk_state[i] == CHUNK_PENDING) {
                    c = i;
                    break;
                }
                if (pf->chunk_state[i] == CHUNK_CLAIMED) {
                    any_pending = true; /* work in flight; more may follow */
                }
            }
            if (c != (size_t)-1) {
                break;
            }

            /* Nothing claimable: window is exhausted or all claimed/done. */
            {
                size_t k;
                bool all_done = true;
                for (k = 0; k < pf->chunk_count; ++k) {
                    if (pf->chunk_state[k] != CHUNK_DONE &&
                        pf->chunk_state[k] != CHUNK_FAILED) {
                        all_done = false;
                        break;
                    }
                }
                if (all_done) {
                    pthread_mutex_unlock(&pf->lock);
                    http_session_close(sess);
                    free(buf);
                    return NULL; /* finished */
                }
            }
            if (any_pending || first + pf->ring_size / PREFETCH_CHUNK_SIZE < pf->chunk_count) {
                /* In-flight work may free the window; wait for progress. */
                pthread_cond_wait(&pf->work_avail, &pf->lock);
                continue;
            }
            /* Everything remaining is done or failed and the window is
             * ahead of it: the reader stopped consuming. Retire. */
            pthread_cond_wait(&pf->work_avail, &pf->lock);
        }
        pf->chunk_state[c] = CHUNK_CLAIMED;
        pthread_mutex_unlock(&pf->lock);

        off = chunk_start(c);
        want = (size_t)(pf->total_size - off);
        if (want > PREFETCH_CHUNK_SIZE) {
            want = PREFETCH_CHUNK_SIZE;
        }

        /* off is relative to the stream; the origin is asked at base + off,
         * while the ring keeps using the relative offset. */
        fetched = http_client_get_session(&sess, pf->url, pf->base + off,
                                          want, buf, want, &r);
        if (!canary_ok(buf, PREFETCH_CHUNK_SIZE)) {
            canary_report("workerbuf", pf, c);
        }
        if (!fetched ||
            !HTTP_IS_OK(r.status) || !r.partial || r.body_len != want) {
            pthread_mutex_lock(&pf->lock);
            if (pf->chunk_state[c] == CHUNK_CLAIMED) {
                pf->chunk_state[c] = CHUNK_FAILED;
            }
            pf->read_failed = true;
            pthread_cond_broadcast(&pf->data_avail);
            pthread_cond_broadcast(&pf->work_avail);
            pthread_mutex_unlock(&pf->lock);
            if (HTTP_IS_OK(r.status) && !r.partial) {
                /* A 200 answer to a Range request means the body starts at
                 * byte 0, not at the requested offset: accepting it would
                 * stream wrong bytes into the ring buffer silently and the
                 * install would only fail much later at the digest check. */
                LOG_ERROR("prefetch: server ignored the range request for "
                           "chunk %zu at offset %llu (HTTP %d)",
                           c, (unsigned long long)off, r.status);
            } else {
                LOG_WARN("prefetch: chunk %zu failed at offset %llu (HTTP %d)",
                         c, (unsigned long long)off, r.status);
            }
            http_session_close(sess);
            free(buf);
            return NULL;
        }

        pthread_mutex_lock(&pf->lock);
        {
            size_t ring_pos = (size_t)(off % pf->ring_size);
            size_t first_part = pf->ring_size - ring_pos;
            if (first_part > want) {
                first_part = want;
            }
            memcpy(pf->ring + ring_pos, buf, first_part);
            if (want > first_part) {
                memcpy(pf->ring, buf + first_part, want - first_part);
            }
            if (pf->chunk_state[c] == CHUNK_CLAIMED) {
                pf->chunk_state[c] = CHUNK_DONE;
                {
                    uint64_t end = off + want;
                    if (end > pf->filled_bytes) {
                        pf->filled_bytes = end;
                    }
                }
            }
            aborting = pf->aborting;
            pf_intact(pf, "after-ring-write");
            pthread_cond_broadcast(&pf->data_avail);
            pthread_cond_broadcast(&pf->work_avail);
        }
        pthread_mutex_unlock(&pf->lock);

        if (aborting) {
            http_session_close(sess);
            free(buf);
            return NULL;
        }
    }
}

prefetch_t* prefetch_start(const char* url, uint64_t base, uint64_t total_size,
                           int connections)
{
    prefetch_t* pf;

    if (!url || total_size == 0) {
        return NULL;
    }
    if (connections < 1) {
        connections = 1;
    }
    if (connections > PREFETCH_MAX_CONNS) {
        connections = PREFETCH_MAX_CONNS;
    }

    pf = (prefetch_t*)calloc(1, sizeof(*pf));
    if (!pf) {
        return NULL;
    }

    pf->magic_head = PF_MAGIC_HEAD;
    pf->magic_tail = PF_MAGIC_TAIL;
    snprintf(pf->url, sizeof(pf->url), "%s", url);
    pf->base = base;
    pf->total_size = total_size;
    pf->connections = connections;
    pf->ring_size = ring_size_for(total_size);

    /* Init the sync primitives BEFORE any allocation that can fail: the
     * err path below locks/broadcasts/joins through them, so they must
     * be valid on every path that reaches it. */
    pthread_mutex_init(&pf->lock, NULL);
    pthread_cond_init(&pf->data_avail, NULL);
    pthread_cond_init(&pf->work_avail, NULL);

    pf->ring = (uint8_t*)malloc(pf->ring_size + PF_CANARY_LEN);
    if (pf->ring) {
        canary_set(pf->ring, pf->ring_size);
        ring_budget_add(pf->ring_size);
    }
    pf->chunk_count = (size_t)((total_size + PREFETCH_CHUNK_SIZE - 1) / PREFETCH_CHUNK_SIZE);
    pf->chunk_state = (uint8_t*)calloc(pf->chunk_count + PF_CANARY_LEN, 1);
    if (pf->chunk_state) {
        canary_set(pf->chunk_state, pf->chunk_count);
    }
    if (!pf->ring || !pf->chunk_state) {
        goto err;
    }

    {
        int i;
        for (i = 0; i < connections; ++i) {
            struct worker_ctx* ctx = (struct worker_ctx*)malloc(sizeof(*ctx));
            if (!ctx) {
                goto err;
            }
            ctx->pf = pf;
            {
                /* Workers call deep into libSceHttp. Size the stack
                 * explicitly instead of trusting the platform default:
                 * memory corruption appeared only with several workers
                 * alive at once, which a stack overrun would explain. */
                pthread_attr_t attr;
                int rc;
                pthread_attr_init(&attr);
                pthread_attr_setstacksize(&attr, PREFETCH_WORKER_STACK);
                rc = pthread_create(&pf->threads[i], &attr, worker_thread, ctx);
                pthread_attr_destroy(&attr);
                if (rc != 0) {
                    free(ctx);
                    goto err;
                }
            }
            ++pf->thread_count;
        }
    }
    pf->threads_spawned = true;
    __atomic_add_fetch(&s_live_engines, 1, __ATOMIC_RELEASE);
    return pf;

err:
    pthread_mutex_lock(&pf->lock);
    pf->aborting = true;
    pthread_cond_broadcast(&pf->data_avail);
    pthread_cond_broadcast(&pf->work_avail);
    pthread_mutex_unlock(&pf->lock);
    {
        int i;
        for (i = 0; i < pf->thread_count; ++i) {
            pthread_join(pf->threads[i], NULL);
        }
    }
    pthread_mutex_destroy(&pf->lock);
    pthread_cond_destroy(&pf->data_avail);
    pthread_cond_destroy(&pf->work_avail);
    if (pf->ring) {
        ring_budget_sub(pf->ring_size);
        free(pf->ring);
    }
    free(pf->chunk_state);
    free(pf);
    return NULL;
}

int64_t prefetch_read(prefetch_t* pf, uint8_t* buf, size_t len)
{
    if (!pf || !buf || len == 0) {
        return -1;
    }
    if (pf->magic_head != PF_MAGIC_HEAD || pf->magic_tail != PF_MAGIC_TAIL) {
        /* Cleared by prefetch_free: a read through a stale engine pointer. */
        canary_report("read-dead-engine", pf, len);
        return -1;
    }

    pthread_mutex_lock(&pf->lock);
    for (;;) {
        uint64_t pos = pf->consumed_bytes;
        uint64_t end = pos + len;
        size_t c0, c1, c;
        bool ready = true;

        if (pos >= pf->total_size) {
            pthread_mutex_unlock(&pf->lock);
            return 0; /* EOF */
        }
        if (pf->read_failed || pf->aborting) {
            /* Fail fast: a stopped or broken stream must not keep serving
             * ring data that its consumer no longer wants. */
            pthread_mutex_unlock(&pf->lock);
            return -1;
        }
        if (end > pf->total_size) {
            end = pf->total_size;
            len = (size_t)(end - pos);
        }

        c0 = chunk_index(pos);
        c1 = chunk_index(end - 1);
        for (c = c0; c <= c1; ++c) {
            if (pf->chunk_state[c] != CHUNK_DONE) {
                ready = false;
                break;
            }
        }

        if (ready) {
            size_t ring_pos = (size_t)(pos % pf->ring_size);
            size_t first_part = pf->ring_size - ring_pos;
            if (first_part > len) {
                first_part = len;
            }
            memcpy(buf, pf->ring + ring_pos, first_part);
            if (len > first_part) {
                memcpy(buf + first_part, pf->ring, len - first_part);
            }
            pf->consumed_bytes = end;
            pthread_cond_broadcast(&pf->work_avail);
            pthread_mutex_unlock(&pf->lock);
            return (int64_t)len;
        }

        if (pf->chunk_state[c] == CHUNK_FAILED || pf->read_failed || pf->aborting) {
            pthread_mutex_unlock(&pf->lock);
            return -1;
        }

        pthread_cond_wait(&pf->data_avail, &pf->lock);
    }
}

void prefetch_abort(prefetch_t* pf)
{
    if (!pf) {
        return;
    }
    pthread_mutex_lock(&pf->lock);
    pf->aborting = true;
    pthread_cond_broadcast(&pf->data_avail);
    pthread_cond_broadcast(&pf->work_avail);
    pthread_mutex_unlock(&pf->lock);
}

void prefetch_free(prefetch_t* pf)
{
    int i;

    if (!pf) {
        return;
    }
    prefetch_abort(pf);
    for (i = 0; i < pf->thread_count; ++i) {
        pthread_join(pf->threads[i], NULL);
    }
    pf_intact(pf, "free");
    pf->magic_head = 0;
    pf->magic_tail = 0;
    pthread_mutex_destroy(&pf->lock);
    pthread_cond_destroy(&pf->data_avail);
    pthread_cond_destroy(&pf->work_avail);
    if (pf->ring) {
        ring_budget_sub(pf->ring_size);
        free(pf->ring);
    }
    free(pf->chunk_state);
    free(pf);
    /* Last: workers are joined and nothing of the engine remains. */
    __atomic_sub_fetch(&s_live_engines, 1, __ATOMIC_RELEASE);
}

void prefetch_stats(const prefetch_t* pf, prefetch_stats_t* out)
{
    if (!pf || !out) {
        return;
    }
    pthread_mutex_lock((pthread_mutex_t*)&pf->lock);
    out->connections = pf->connections;
    out->filled_bytes = pf->filled_bytes;
    out->consumed_bytes = pf->consumed_bytes;
    out->total_bytes = pf->total_size;
    out->ranges_ok = pf->connections > 1;
    pthread_mutex_unlock((pthread_mutex_t*)&pf->lock);
}
