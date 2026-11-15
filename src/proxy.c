/*
 * Remote PKG Installer NextGen
 * Copyright (c) 2025-present AldySan and contributors.
 * Licensed under the GNU General Public License v3.0. See LICENSE for details.
 */
#include "proxy.h"
#include "http_client.h"
#include "log.h"
#include "prefetch.h"
#include "taskman.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROXY_MAX_JOBS     32
#define PROXY_URL_MAX      2048  /* must hold long signed piece URLs */

#define PROXY_BIG_PIECE    (8u * 1024u * 1024u)   /* switch to parallel above */
#define PROXY_CONN_SMALL   1
#define PROXY_CONN_BIG     PREFETCH_DEFAULT_CONNECTIONS

/*
 * How BGFT reads a piece (journal, firmware 14.0): one 16 MiB Range request
 * at a time, each starting where the previous one ended, each on a new
 * connection. Starting a fresh fetch per request left the origin idle
 * between requests and capped a LAN install near 8 MiB/s.
 *
 * So each job keeps one read-ahead engine (multi-connection prefetch) that
 * outlives a single request: a request that starts at the engine's frontier
 * reuses it and finds its bytes already buffered; a request elsewhere
 * restarts it there. A request that arrives while the engine is serving
 * another one (true parallel reads) gets its own single-connection stream,
 * so concurrency never multiplies engines, threads or ring buffers.
 */

struct proxy_piece {
    char url[PROXY_URL_MAX];
    uint64_t size;
    bool ranges_ok;
};

enum stream_kind {
    STREAM_DIRECT = 0,   /* sequential origin stream from byte 0 */
    STREAM_OWN = 1,      /* prefetch engine owned by this stream */
    STREAM_SHARED = 2,   /* the job's read-ahead engine, borrowed */
};

struct proxy_stream {
    enum stream_kind kind;
    const char* mode;    /* diagnostics: direct, new, reuse, parallel, whole */
    prefetch_t* pf;
    http_stream_t* hs;
    uint64_t offset;     /* absolute piece offset of stream byte 0 */
    uint64_t size;       /* bytes this request may read */
    uint64_t pos;
    bool failed;
    bool aborted;
};

struct proxy_job {
    bool used;
    int job_id;
    size_t count;
    struct proxy_piece* pieces;
    /* Reference to the stream currently serving this job (NOT owned by
     * the registry): the serving connection owns the stream and frees it
     * via proxy_stream_close. Kept only so a piece change or job teardown
     * can abort it; always cleared under s_lock before it is freed. */
    struct proxy_stream* stream;
    int stream_piece;

    /* Read-ahead engine. Owned by the job while idle; lent to exactly one
     * stream while engine_busy. engine_pos is the absolute piece offset of
     * the next byte it will return. */
    prefetch_t* engine;
    size_t engine_piece;
    uint64_t engine_pos;
    bool engine_busy;
};

static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
static struct proxy_job s_jobs[PROXY_MAX_JOBS];

static struct proxy_job* find_job(int job_id)
{
    int i;

    for (i = 0; i < PROXY_MAX_JOBS; ++i) {
        if (s_jobs[i].used && s_jobs[i].job_id == job_id) {
            return &s_jobs[i];
        }
    }
    return NULL;
}

/* prefetch_free joins the engine's workers, which can wait for an
 * in-flight 2 MiB fetch. Callers that must not block (the poll thread, a
 * request about to serve data) hand the engine to a short-lived thread. */
static void* engine_free_thread(void* arg)
{
    prefetch_free((prefetch_t*)arg);
    return NULL;
}

static void engine_free_async(prefetch_t* pf)
{
    pthread_t tid;
    pthread_attr_t attr;
    bool started = false;

    if (!pf) {
        return;
    }
    prefetch_abort(pf);
    if (pthread_attr_init(&attr) == 0) {
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        started = pthread_create(&tid, &attr, engine_free_thread, pf) == 0;
        pthread_attr_destroy(&attr);
    }
    if (!started) {
        prefetch_free(pf); /* no thread available: free inline */
    }
}

/* Caller must hold s_lock (the stream is aborted, never freed here). */
static void stream_abort(struct proxy_stream* st)
{
    if (!st) {
        return;
    }
    /* Written under s_lock, polled lock-free by the reader. */
    __atomic_store_n(&st->aborted, true, __ATOMIC_RELEASE);
    if (st->kind != STREAM_DIRECT && st->pf) {
        prefetch_abort(st->pf);
    }
}

bool proxy_register(int job_id, const char* const* urls,
                    const uint64_t* sizes, const bool* ranges_ok,
                    size_t count)
{
    struct proxy_job* job = NULL;
    int i;

    if (!urls || !sizes || count == 0) {
        return false;
    }

    pthread_mutex_lock(&s_lock);
    if (find_job(job_id)) {
        pthread_mutex_unlock(&s_lock);
        return false; /* already registered */
    }
    for (i = 0; i < PROXY_MAX_JOBS; ++i) {
        if (!s_jobs[i].used) {
            job = &s_jobs[i];
            break;
        }
    }
    if (!job) {
        pthread_mutex_unlock(&s_lock);
        LOG_WARN("proxy: registry full");
        return false;
    }

    memset(job, 0, sizeof(*job));
    job->pieces = (struct proxy_piece*)calloc(count, sizeof(*job->pieces));
    if (!job->pieces) {
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    for (i = 0; i < (int)count; ++i) {
        if (!urls[i]) {
            free(job->pieces);
            job->pieces = NULL;
            pthread_mutex_unlock(&s_lock);
            return false;
        }
        snprintf(job->pieces[i].url, sizeof(job->pieces[i].url), "%s", urls[i]);
        job->pieces[i].size = sizes[i];
        job->pieces[i].ranges_ok = ranges_ok ? ranges_ok[i] : false;
    }
    job->used = true;
    job->job_id = job_id;
    job->count = count;
    job->stream_piece = -1;
    pthread_mutex_unlock(&s_lock);
    return true;
}

void proxy_unregister(int job_id)
{
    struct proxy_job* job;
    prefetch_t* idle_engine = NULL;

    pthread_mutex_lock(&s_lock);
    job = find_job(job_id);
    if (job) {
        if (job->stream) {
            /* Abort the live stream so its serving connection unwinds and
             * frees it (it owns the stream). */
            stream_abort(job->stream);
            job->stream = NULL;
        }
        job->stream_piece = -1;
        if (job->engine) {
            if (job->engine_busy) {
                /* Lent out: abort it; the borrower finds the job gone on
                 * close and frees the engine itself. */
                prefetch_abort(job->engine);
            } else {
                idle_engine = job->engine;
            }
            job->engine = NULL;
            job->engine_busy = false;
        }
        free(job->pieces);
        job->pieces = NULL;
        job->used = false;
        job->job_id = 0;
    }
    pthread_mutex_unlock(&s_lock);

    /* Never join workers on the poll thread. */
    engine_free_async(idle_engine);
}

bool proxy_piece_size(int job_id, size_t piece, uint64_t* size)
{
    struct proxy_job* job;
    bool ok = false;

    pthread_mutex_lock(&s_lock);
    job = find_job(job_id);
    if (job && piece < job->count) {
        if (size) {
            *size = job->pieces[piece].size;
        }
        ok = true;
    }
    pthread_mutex_unlock(&s_lock);
    return ok;
}

void* proxy_stream_open(int job_id, size_t piece, uint64_t offset,
                        uint64_t length)
{
    char url[PROXY_URL_MAX];
    uint64_t size = 0;
    bool ranges_ok = false;
    struct proxy_stream* st;
    struct proxy_job* job;
    prefetch_t* stale_engine = NULL;
    bool use_engine = false;   /* serve from the job's read-ahead engine */
    bool reuse = false;        /* ... and it is already at `offset` */

    url[0] = '\0';

    st = (struct proxy_stream*)calloc(1, sizeof(*st));
    if (!st) {
        return NULL;
    }

    pthread_mutex_lock(&s_lock);
    job = find_job(job_id);
    if (job && piece < job->count) {
        snprintf(url, sizeof(url), "%s", job->pieces[piece].url);
        size = job->pieces[piece].size;
        ranges_ok = job->pieces[piece].ranges_ok;
        if (job->stream && job->stream_piece != (int)piece) {
            /* BGFT moved on: abort the previous stream (aborted reads
             * fail immediately, so its connection unwinds and frees it). */
            stream_abort(job->stream);
            job->stream = NULL;
            job->stream_piece = -1;
        }
        if (ranges_ok && length > 0 && offset < size &&
            length <= size - offset && !job->engine_busy) {
            use_engine = true;
            if (job->engine && job->engine_piece == piece &&
                job->engine_pos == offset) {
                reuse = true;
                st->pf = job->engine; /* lent to this stream from now on */
            } else {
                stale_engine = job->engine; /* wrong place: restart */
                job->engine = NULL;
            }
            /* Claim it now so a concurrent request takes the parallel path
             * instead of starting a second engine. */
            job->engine_busy = true;
        }
    }
    pthread_mutex_unlock(&s_lock);

    engine_free_async(stale_engine);

    if (size == 0 || url[0] == '\0' || length == 0 || offset >= size ||
        length > size - offset) {
        goto fail;
    }
    if (offset > 0 && !ranges_ok) {
        /* The sequential fallback always starts at byte 0. */
        LOG_WARN("proxy: job %d piece %zu: range at %llu needs an origin "
                 "that supports Range", job_id, piece,
                 (unsigned long long)offset);
        goto fail;
    }

    st->offset = offset;
    st->size = length;

    if (use_engine) {
        st->kind = STREAM_SHARED;
        if (reuse) {
            st->mode = "reuse";
        } else {
            /* The engine reads from `offset` to the end of the piece so the
             * next contiguous request finds it already running. */
            int conns = (size - offset >= PROXY_BIG_PIECE) ? PROXY_CONN_BIG
                                                           : PROXY_CONN_SMALL;
            prefetch_t* pf = prefetch_start(url, offset, size - offset, conns);

            pthread_mutex_lock(&s_lock);
            job = find_job(job_id);
            if (job && pf) {
                job->engine = pf;
                job->engine_piece = piece;
                job->engine_pos = offset;
                st->pf = pf;
            } else if (job) {
                job->engine_busy = false; /* could not start: release claim */
            }
            pthread_mutex_unlock(&s_lock);
            if (pf && !st->pf) {
                engine_free_async(pf); /* job vanished meanwhile */
            }
            st->mode = "new";
        }
        if (!st->pf) {
            /* Engine could not start; the claim was released above. */
            free(st);
            return NULL;
        }
    } else if (ranges_ok) {
        /* Parallel request while the engine is busy: one connection,
         * exactly this range. */
        st->kind = STREAM_OWN;
        st->mode = "parallel";
        st->pf = prefetch_start(url, offset, length, PROXY_CONN_SMALL);
        if (!st->pf) {
            goto fail;
        }
    } else {
        st->kind = STREAM_DIRECT;
        st->mode = "direct";
        st->hs = http_stream_open(url);
        if (!st->hs) {
            goto fail;
        }
    }

    pthread_mutex_lock(&s_lock);
    job = find_job(job_id);
    if (!job) {
        pthread_mutex_unlock(&s_lock);
        proxy_stream_close(job_id, st);
        return NULL;
    }
    if (!job->stream) {
        job->stream = st;
        job->stream_piece = (int)piece;
    }
    pthread_mutex_unlock(&s_lock);
    return st;

fail:
    /* Only reached without an engine claim: a claim is taken only for a
     * valid request, and its failures return above. */
    free(st);
    return NULL;
}

const char* proxy_stream_mode(const void* stream)
{
    const struct proxy_stream* st = (const struct proxy_stream*)stream;
    return (st && st->mode) ? st->mode : "-";
}

int64_t proxy_stream_read(void* stream, uint8_t* buf, size_t len)
{
    struct proxy_stream* st = (struct proxy_stream*)stream;
    int64_t n;

    if (!st || !buf || len == 0) {
        return -1;
    }
    if (__atomic_load_n(&st->aborted, __ATOMIC_ACQUIRE)) {
        st->failed = true;
        return -1;
    }
    if (st->pos >= st->size) {
        return 0;
    }
    /* A shared engine runs to the end of the piece: never hand out more
     * than this request asked for. */
    if ((uint64_t)len > st->size - st->pos) {
        len = (size_t)(st->size - st->pos);
    }
    if (st->kind == STREAM_DIRECT) {
        n = http_stream_read(st->hs, buf, len);
        if (n == 0) {
            /* The response headers promised `size` bytes: EOF before that
             * is a short body and must surface as an error. */
            n = -1;
        }
    } else {
        n = prefetch_read(st->pf, buf, len);
        if (n == 0) {
            n = -1; /* engine ended before this request's bytes */
        }
    }
    if (n < 0) {
        st->failed = true;
        return -1;
    }
    st->pos += (uint64_t)n;
    return n;
}

void proxy_stream_close(int job_id, void* stream)
{
    struct proxy_stream* st = (struct proxy_stream*)stream;
    struct proxy_job* job;
    prefetch_t* to_free = NULL;

    if (!st) {
        return;
    }
    /* Drop the registry's reference first (under the lock) so nothing can
     * abort or double-free the stream we are about to free. */
    pthread_mutex_lock(&s_lock);
    job = find_job(job_id);
    if (job && job->stream == st) {
        job->stream = NULL;
        job->stream_piece = -1;
    }
    if (st->kind == STREAM_SHARED) {
        if (job && job->engine == st->pf && job->engine_busy) {
            /* Return the engine. It stays usable only if every byte it
             * produced went to this request's client in order. */
            job->engine_busy = false;
            job->engine_pos = st->offset + st->pos;
            if (st->failed) {
                job->engine = NULL;
                to_free = st->pf;
            }
        } else {
            to_free = st->pf; /* job torn down or engine replaced */
        }
        st->pf = NULL;
    }
    pthread_mutex_unlock(&s_lock);

    if (st->kind == STREAM_SHARED) {
        engine_free_async(to_free);
    } else if (st->kind == STREAM_OWN) {
        prefetch_free(st->pf);
    } else {
        http_stream_close(st->hs);
    }
    free(st);
}
