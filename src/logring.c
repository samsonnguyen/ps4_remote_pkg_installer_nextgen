/*
 * Remote PKG Installer NextGen
 * Copyright (c) 2025-present AldySan and contributors.
 * Licensed under the GNU General Public License v3.0. See LICENSE for details.
 */
#include "log.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/*
 * stdio is NOT thread-safe in this app. The OpenOrbis musl only turns on
 * FILE locking (libc.threaded) inside its own pthread_create, but the app's
 * threads come from libkernel's pthread_create, so stdout and every
 * fopen'd FILE keep lock = -1 ("never lock"). Concurrent printf calls then
 * race on stdout's buffer pointers and can run past its static buffer:
 * the crash journal showed a garbage stdout FILE (locking_putc, address
 * 0x21 = '!') and heap metadata failures (__bin_chunk) once several
 * threads logged at once. Every write to the shared sinks (stdout and
 * dbglogger's socket/file) goes through this one mutex.
 */
static pthread_mutex_t s_out_lock = PTHREAD_MUTEX_INITIALIZER;
static bool s_sinks_open = true;

void log_emit(const char* level, const char* fmt, ...)
{
    char msg[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    pthread_mutex_lock(&s_out_lock);
    if (s_sinks_open) {
        printf("[%s] %s\n", level, msg);
        dbglogger_log("[%s] %s\n", level, msg);
    }
    pthread_mutex_unlock(&s_out_lock);

    log_ring_add(level, "%s", msg);
}

void log_sinks_close(void)
{
    pthread_mutex_lock(&s_out_lock);
    if (s_sinks_open) {
        s_sinks_open = false;
        fflush(stdout);
        dbglogger_stop();
    }
    pthread_mutex_unlock(&s_out_lock);
}

static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
static char s_ring[LOG_RING_CAPACITY][LOG_RING_ENTRY_MAX];
static int s_count = 0;   /* total entries kept (bounded by capacity) */
static int s_start = 0;   /* ring start index */

void log_ring_add(const char* level, const char* fmt, ...)
{
    va_list ap;
    char entry[LOG_RING_ENTRY_MAX];
    char line[LOG_RING_ENTRY_MAX];
    int slot;

    va_start(ap, fmt);
    vsnprintf(entry, sizeof(entry), fmt, ap);
    va_end(ap);

    snprintf(line, sizeof(line), "%s %s", level ? level : "LOG", entry);

    pthread_mutex_lock(&s_lock);
    if (s_count == LOG_RING_CAPACITY) {
        s_start = (s_start + 1) % LOG_RING_CAPACITY;
        s_count = LOG_RING_CAPACITY - 1;
    }
    slot = (s_start + s_count) % LOG_RING_CAPACITY;
    strlcpy(s_ring[slot], line, sizeof(s_ring[slot]));
    ++s_count;
    pthread_mutex_unlock(&s_lock);
}

bool log_ring_get(int index, char* out, size_t outsz)
{
    bool ok = false;

    if (!out || outsz == 0) {
        return false;
    }
    out[0] = '\0';

    pthread_mutex_lock(&s_lock);
    if (index >= 0 && index < s_count) {
        int slot = (s_start + index) % LOG_RING_CAPACITY;
        strlcpy(out, s_ring[slot], outsz);
        ok = true;
    }
    pthread_mutex_unlock(&s_lock);
    return ok;
}

int log_ring_count(void)
{
    int count;

    pthread_mutex_lock(&s_lock);
    count = s_count;
    pthread_mutex_unlock(&s_lock);
    return count;
}
