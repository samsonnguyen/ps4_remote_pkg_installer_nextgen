/*
 * Remote PKG Installer NextGen
 * Copyright (c) 2025-present AldySan and contributors.
 * Licensed under the GNU General Public License v3.0. See LICENSE for details.
 *
 * Debug heap checker (built only with DEBUG_HEAP=1).
 *
 * The linker routes malloc/calloc/realloc/memalign/free through the
 * __wrap_* functions below (ld --wrap), which sit on top of musl's
 * allocator and add:
 *   - a 32-byte header (magic, size, caller of malloc, caller of free);
 *   - a 32-byte guard after every block, checked at free;
 *   - poisoning and a quarantine for freed blocks up to 256 KiB, so a
 *     write after free is caught when the block leaves quarantine (or at
 *     the periodic heapcheck_scan) instead of corrupting a reused block;
 *   - double frees are journaled and NOT passed on, so the app survives.
 *
 * Every finding goes to /data/rpi_nextgen_heap.txt through a raw write()
 * before anything else happens, so it survives even if the process dies
 * right after. Nothing here may allocate.
 */

#ifdef DEBUG_HEAP

#include "heapcheck.h"
#include "diag.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void* __real_malloc(size_t n);
void __real_free(void* p);

#define HC_FILE        "/data/rpi_nextgen_heap.txt"
#define HC_MAGIC_LIVE  0xA110C8EDu
#define HC_MAGIC_FREED 0xF4EEDF4Eu
#define HC_HDR         32u
#define HC_TAIL        32u
#define HC_TAIL_BYTE   0xABu
#define HC_POISON      0xDDu
#define HC_Q_SLOTS     4096
#define HC_Q_MAX_BLOCK (256u * 1024u)
#define HC_Q_MAX_BYTES (24u * 1024u * 1024u)
#define HC_MAX_LOGS    200
#define HC_APP_LO      0x400000ULL
#define HC_APP_HI      0x600000ULL

struct hc_hdr {
    uint32_t magic;
    uint32_t align_off;   /* user pointer - raw pointer, minus HC_HDR */
    uint64_t size;
    uint64_t alloc_ra;
    uint64_t free_ra;
};

_Static_assert(sizeof(struct hc_hdr) == HC_HDR, "header must stay 32 bytes");

static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
static int s_fd = -1;
static int s_logs = 0;
static uint8_t* s_q[HC_Q_SLOTS];
static int s_q_head = 0;       /* next slot to fill (oldest when full) */
static int s_q_count = 0;
static size_t s_q_bytes = 0;

static uint64_t s_allocs = 0;
static uint64_t s_frees = 0;
static uint64_t s_live_bytes = 0;
static uint64_t s_events = 0;
static uint64_t s_foreign = 0;

/* Return addresses inside the app are journaled as ELF offsets so they map
 * straight onto build/symbols.txt; anything else stays absolute. */
static uint64_t hc_ra(const void* ra)
{
    uint64_t v = (uint64_t)(uintptr_t)ra;

    return (v >= HC_APP_LO && v < HC_APP_HI) ? v - HC_APP_LO : v;
}

/* Caller holds s_lock. */
static void hc_log(const char* fmt, ...)
{
    char line[320];
    struct timespec now;
    struct tm tm;
    va_list ap;
    int n;
    int m;

    ++s_events;
    if (s_logs >= HC_MAX_LOGS) {
        return;
    }
    if (s_fd < 0) {
        s_fd = open(HC_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (s_fd < 0) {
            return;
        }
    }
    ++s_logs;
    clock_gettime(CLOCK_REALTIME, &now);
    gmtime_r(&now.tv_sec, &tm);
    n = snprintf(line, sizeof(line), "%02d:%02d:%02d [%.39s] ", tm.tm_hour,
                 tm.tm_min, tm.tm_sec, diag_step());
    if (n < 0 || n >= (int)sizeof(line)) {
        n = 0;
    }
    va_start(ap, fmt);
    m = vsnprintf(line + n, sizeof(line) - (size_t)n - 1, fmt, ap);
    va_end(ap);
    if (m < 0) {
        m = 0;
    }
    n += m;
    if (n > (int)sizeof(line) - 2) {
        n = (int)sizeof(line) - 2;
    }
    line[n++] = '\n';
    write(s_fd, line, (size_t)n);
}

/* 32 bytes as hex: what overwrote a guard often says who did it (ASCII
 * HTTP headers, a pointer into a known region, a length). */
static void hc_hex32(char* out, size_t outsz, const uint8_t* p)
{
    size_t i;
    size_t o = 0;

    for (i = 0; i < 32 && o + 3 < outsz; ++i) {
        o += (size_t)snprintf(out + o, outsz - o, "%02x", p[i]);
    }
    out[o < outsz ? o : outsz - 1] = '\0';
}

static struct hc_hdr* hc_header(void* user)
{
    return (struct hc_hdr*)((uint8_t*)user - HC_HDR);
}

static uint8_t* hc_raw(struct hc_hdr* h, void* user)
{
    return (uint8_t*)user - HC_HDR - h->align_off;
}

static void* hc_alloc(size_t size, size_t align, const void* ra)
{
    size_t extra = (align > 16) ? align : 0;
    size_t total;
    uint8_t* raw;
    uint8_t* user;
    struct hc_hdr* h;

    if (size > ((size_t)-1) / 2) {
        return NULL;
    }
    total = HC_HDR + extra + size + HC_TAIL;
    raw = (uint8_t*)__real_malloc(total);
    if (!raw) {
        return NULL;
    }
    user = raw + HC_HDR;
    if (extra) {
        uintptr_t u = ((uintptr_t)user + align - 1) & ~(uintptr_t)(align - 1);
        user = (uint8_t*)u;
    }
    h = hc_header(user);
    h->magic = HC_MAGIC_LIVE;
    h->align_off = (uint32_t)(user - HC_HDR - raw);
    h->size = size;
    h->alloc_ra = hc_ra(ra);
    h->free_ra = 0;
    memset(user + size, HC_TAIL_BYTE, HC_TAIL);

    pthread_mutex_lock(&s_lock);
    ++s_allocs;
    s_live_bytes += size;
    pthread_mutex_unlock(&s_lock);
    return user;
}

/* Caller holds s_lock. Verifies a quarantined block is still fully
 * poisoned, then returns it to musl. */
static void hc_release_locked(uint8_t* user)
{
    struct hc_hdr* h = hc_header(user);
    size_t i;

    if (h->magic != HC_MAGIC_FREED) {
        char hex[72];
        hc_hex32(hex, sizeof(hex), (const uint8_t*)h);
        hc_log("QUARANTINE-HDR-SMASHED p=%p hdr=%s", (void*)user, hex);
    } else {
        for (i = 0; i < h->size; ++i) {
            if (user[i] != HC_POISON) {
                char hex[72];
                size_t at = (i + 32 <= h->size) ? i : (h->size >= 32 ? h->size - 32 : 0);
                hc_hex32(hex, sizeof(hex), user + at);
                hc_log("USE-AFTER-FREE-WRITE p=%p size=%llu off=%llu alloc_ra=%llx "
                       "free_ra=%llx bytes@%llu=%s",
                       (void*)user, (unsigned long long)h->size,
                       (unsigned long long)i, (unsigned long long)h->alloc_ra,
                       (unsigned long long)h->free_ra, (unsigned long long)at, hex);
                break;
            }
        }
        for (i = 0; i < HC_TAIL; ++i) {
            if (user[h->size + i] != HC_TAIL_BYTE) {
                char hex[72];
                hc_hex32(hex, sizeof(hex), user + h->size);
                hc_log("TAIL-SMASHED-AFTER-FREE p=%p size=%llu alloc_ra=%llx "
                       "free_ra=%llx tail=%s",
                       (void*)user, (unsigned long long)h->size,
                       (unsigned long long)h->alloc_ra,
                       (unsigned long long)h->free_ra, hex);
                break;
            }
        }
    }
    __real_free(hc_raw(h, user));
}

static void hc_free(void* p, const void* ra)
{
    struct hc_hdr* h;
    uint8_t* user = (uint8_t*)p;
    size_t i;

    if (!p) {
        return;
    }
    h = hc_header(p);

    pthread_mutex_lock(&s_lock);
    if (h->magic == HC_MAGIC_FREED) {
        hc_log("DOUBLE-FREE p=%p size=%llu alloc_ra=%llx first_free_ra=%llx "
               "now_ra=%llx",
               p, (unsigned long long)h->size, (unsigned long long)h->alloc_ra,
               (unsigned long long)h->free_ra, (unsigned long long)hc_ra(ra));
        pthread_mutex_unlock(&s_lock);
        return; /* swallowed: the block is still in quarantine */
    }
    if (h->magic != HC_MAGIC_LIVE) {
        /* Not ours (allocated before the wrap or by code that bypasses
         * it) or a smashed header. Journal it and hand it to musl as is. */
        ++s_foreign;
        {
            char hex[72];
            hc_hex32(hex, sizeof(hex), (const uint8_t*)h);
            hc_log("FOREIGN-OR-SMASHED-FREE p=%p now_ra=%llx hdr=%s", p,
                   (unsigned long long)hc_ra(ra), hex);
        }
        pthread_mutex_unlock(&s_lock);
        __real_free(p);
        return;
    }

    for (i = 0; i < HC_TAIL; ++i) {
        if (user[h->size + i] != HC_TAIL_BYTE) {
            char hex[72];
            hc_hex32(hex, sizeof(hex), user + h->size);
            hc_log("OVERRUN p=%p size=%llu alloc_ra=%llx free_ra=%llx "
                   "first_bad=+%llu tail=%s",
                   p, (unsigned long long)h->size, (unsigned long long)h->alloc_ra,
                   (unsigned long long)hc_ra(ra), (unsigned long long)i, hex);
            break;
        }
    }

    h->magic = HC_MAGIC_FREED;
    h->free_ra = hc_ra(ra);
    ++s_frees;
    s_live_bytes -= (h->size <= s_live_bytes) ? h->size : s_live_bytes;

    if (h->size > HC_Q_MAX_BLOCK) {
        pthread_mutex_unlock(&s_lock);
        __real_free(hc_raw(h, p));
        return;
    }

    memset(user, HC_POISON, h->size);
    /* Make room: release the oldest blocks first. */
    while (s_q_count > 0 &&
           (s_q_count >= HC_Q_SLOTS || s_q_bytes + h->size > HC_Q_MAX_BYTES)) {
        int oldest = (s_q_head - s_q_count + HC_Q_SLOTS) % HC_Q_SLOTS;
        uint8_t* old = s_q[oldest];
        s_q[oldest] = NULL;
        --s_q_count;
        s_q_bytes -= hc_header(old)->size;
        hc_release_locked(old);
    }
    s_q[s_q_head] = user;
    s_q_head = (s_q_head + 1) % HC_Q_SLOTS;
    ++s_q_count;
    s_q_bytes += h->size;
    pthread_mutex_unlock(&s_lock);
}

void* __wrap_malloc(size_t n)
{
    return hc_alloc(n, 0, __builtin_return_address(0));
}

void* __wrap_calloc(size_t count, size_t size)
{
    void* p;

    if (size && count > ((size_t)-1) / size) {
        return NULL;
    }
    p = hc_alloc(count * size, 0, __builtin_return_address(0));
    if (p) {
        memset(p, 0, count * size);
    }
    return p;
}

void* __wrap_memalign(size_t align, size_t n)
{
    if (align < 16 || (align & (align - 1)) != 0) {
        align = 16;
    }
    return hc_alloc(n, align, __builtin_return_address(0));
}

void __wrap_free(void* p)
{
    hc_free(p, __builtin_return_address(0));
}

void* __wrap_realloc(void* p, size_t n)
{
    const void* ra = __builtin_return_address(0);
    struct hc_hdr* h;
    void* q;
    size_t keep;

    if (!p) {
        return hc_alloc(n, 0, ra);
    }
    h = hc_header(p);
    if (h->magic != HC_MAGIC_LIVE) {
        pthread_mutex_lock(&s_lock);
        {
            char hex[72];
            hc_hex32(hex, sizeof(hex), (const uint8_t*)h);
            hc_log("REALLOC-BAD-BLOCK p=%p magic=%08x now_ra=%llx hdr=%s", p,
                   h->magic, (unsigned long long)hc_ra(ra), hex);
        }
        pthread_mutex_unlock(&s_lock);
        return NULL; /* never hand musl a block we cannot vouch for */
    }
    q = hc_alloc(n, 0, ra);
    if (!q) {
        return NULL;
    }
    keep = (h->size < n) ? (size_t)h->size : n;
    memcpy(q, p, keep);
    hc_free(p, ra);
    return q;
}

void heapcheck_scan(void)
{
    int i;
    int idx;

    /* Re-verifies every quarantined block so a write after free is
     * reported within one heartbeat, not only when the block is evicted. */
    pthread_mutex_lock(&s_lock);
    for (i = 0; i < s_q_count; ++i) {
        uint8_t* user;
        struct hc_hdr* h;
        size_t k;

        idx = (s_q_head - s_q_count + i + HC_Q_SLOTS) % HC_Q_SLOTS;
        user = s_q[idx];
        if (!user) {
            continue;
        }
        h = hc_header(user);
        if (h->magic != HC_MAGIC_FREED) {
            char hex[72];
            hc_hex32(hex, sizeof(hex), (const uint8_t*)h);
            hc_log("SCAN-HDR-SMASHED p=%p hdr=%s", (void*)user, hex);
            continue;
        }
        for (k = 0; k < h->size; ++k) {
            if (user[k] != HC_POISON) {
                char hex[72];
                size_t at = (k + 32 <= h->size) ? k : (h->size >= 32 ? h->size - 32 : 0);
                hc_hex32(hex, sizeof(hex), user + at);
                hc_log("SCAN-USE-AFTER-FREE-WRITE p=%p size=%llu off=%llu "
                       "alloc_ra=%llx free_ra=%llx bytes@%llu=%s",
                       (void*)user, (unsigned long long)h->size,
                       (unsigned long long)k, (unsigned long long)h->alloc_ra,
                       (unsigned long long)h->free_ra, (unsigned long long)at, hex);
                memset(user, HC_POISON, h->size); /* report each write once */
                break;
            }
        }
    }
    pthread_mutex_unlock(&s_lock);
}

void heapcheck_stats(char* out, size_t outsz)
{
    pthread_mutex_lock(&s_lock);
    snprintf(out, outsz, "heap=%lluK allocs=%llu frees=%llu q=%d events=%llu foreign=%llu",
             (unsigned long long)(s_live_bytes >> 10),
             (unsigned long long)s_allocs, (unsigned long long)s_frees, s_q_count,
             (unsigned long long)s_events, (unsigned long long)s_foreign);
    pthread_mutex_unlock(&s_lock);
}

#endif /* DEBUG_HEAP */
