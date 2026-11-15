/*
 * Remote PKG Installer NextGen
 * Copyright (c) 2025-present AldySan and contributors.
 * Licensed under the GNU General Public License v3.0. See LICENSE for details.
 *
 * Flight recorder implementation. File writes go to the app sandbox
 * (/data) so they survive the process and can be pulled over FTP/USB.
 */

#include "diag.h"
#include "version.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DIAG_BOOT_FILE  APP_WORK_DIR "/rpi_nextgen_boot.txt"
#define DIAG_CRASH_FILE APP_WORK_DIR "/rpi_nextgen_crash.txt"

static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
static struct timespec s_t0;
static bool s_t0_set = false;
static char s_step[40] = "pre-start";
static int s_crash_fd = -1;

/* CLOCK_REALTIME, not CLOCK_MONOTONIC: on firmware 14.0 the toolchain's
 * monotonic clock ran about 20x slower than real time (a 16 MiB range
 * journaled as 80 ms on a link that took 1.6 s to carry it), which made
 * every journal timing meaningless. The wall clock matched the console's
 * own clock in the crash journal. */
#define DIAG_CLOCK CLOCK_REALTIME

static double mono_sec(void)
{
    struct timespec ts;

    clock_gettime(DIAG_CLOCK, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

static double uptime_locked(void)
{
    return s_t0_set ? mono_sec() - ((double)s_t0.tv_sec +
               (double)s_t0.tv_nsec / 1000000000.0) : 0.0;
}

void diag_note(const char* step)
{
    FILE* f;
    double t;

    if (!step) {
        return;
    }

    pthread_mutex_lock(&s_lock);
    if (!s_t0_set) {
        clock_gettime(DIAG_CLOCK, &s_t0);
        s_t0_set = true;
        f = fopen(DIAG_BOOT_FILE, "w");
        if (f) {
            fprintf(f, "%s v%s boot\n", APP_SHORT_NAME, APP_VERSION);
            fclose(f);
        }
    }
    t = uptime_locked();
    snprintf(s_step, sizeof(s_step), "%s", step);
    pthread_mutex_unlock(&s_lock);

    f = fopen(DIAG_BOOT_FILE, "a");
    if (f) {
        fprintf(f, "t=%8.3fs %s\n", t, step);
        fclose(f);
    }
}

#define DIAG_PROBE_MAX 96
static int s_probe_count = 0;

void diag_notef(const char* fmt, ...)
{
    char note[160];
    va_list ap;

    if (__atomic_fetch_add(&s_probe_count, 1, __ATOMIC_RELAXED) >= DIAG_PROBE_MAX) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(note, sizeof(note), fmt, ap);
    va_end(ap);
    diag_note(note);
}

const char* diag_step(void)
{
    return s_step;
}

double diag_uptime(void)
{
    double t;

    pthread_mutex_lock(&s_lock);
    t = uptime_locked();
    pthread_mutex_unlock(&s_lock);
    return t;
}

void diag_hud(char* out, size_t outsz)
{
    if (!out || outsz == 0) {
        return;
    }
    snprintf(out, outsz, "v%s  t=%3.0fs  %s", APP_VERSION, diag_uptime(),
             diag_step());
}

/* Heartbeat journal: one line every few seconds for the whole run, so a
 * process the system kills outright (a CE error code, no fault handler)
 * still leaves the minutes before the kill on disk. Rotates to .old at
 * DIAG_BEAT_MAX_LINES so it never grows without bound (~2 h per file at
 * one line per 5 s). Only the main loop writes it. */
#define DIAG_BEAT_FILE     APP_WORK_DIR "/rpi_nextgen_beat.txt"
#define DIAG_BEAT_OLD_FILE APP_WORK_DIR "/rpi_nextgen_beat.old.txt"
#define DIAG_BEAT_MAX_LINES 1500

static int s_beat_lines = -1; /* -1: not opened this run yet */

void diag_beat(const char* line)
{
    FILE* f;
    struct timespec now;
    struct tm tm;

    if (!line) {
        return;
    }
    if (s_beat_lines < 0 || s_beat_lines >= DIAG_BEAT_MAX_LINES) {
        if (s_beat_lines >= 0) {
            rename(DIAG_BEAT_FILE, DIAG_BEAT_OLD_FILE);
        }
        f = fopen(DIAG_BEAT_FILE, "w");
        if (!f) {
            return;
        }
        fprintf(f, "%s v%s heartbeat\n", APP_SHORT_NAME, APP_VERSION);
        fclose(f);
        s_beat_lines = 0;
    }

    clock_gettime(CLOCK_REALTIME, &now);
    gmtime_r(&now.tv_sec, &tm);
    f = fopen(DIAG_BEAT_FILE, "a");
    if (f) {
        fprintf(f, "%02d:%02d:%02d %s\n", tm.tm_hour, tm.tm_min, tm.tm_sec, line);
        fclose(f);
        ++s_beat_lines;
    }
}

int diag_crash_fd(void)
{
    pthread_mutex_lock(&s_lock);
    if (s_crash_fd < 0) {
        s_crash_fd = open(DIAG_CRASH_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    }
    pthread_mutex_unlock(&s_lock);
    return s_crash_fd;
}

void diag_crash_note(const char* fmt, ...)
{
    char line[256];
    char stamped[320];
    struct timespec now;
    struct tm tm;
    va_list ap;
    int fd;

    if (!fmt) {
        return;
    }

    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    clock_gettime(CLOCK_REALTIME, &now);
    gmtime_r(&now.tv_sec, &tm);
    snprintf(stamped, sizeof(stamped), "[%04d-%02d-%02d %02d:%02d:%02d UTC] %s\n",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, line);

    /* Raw write() on the pre-opened fd: this path must stay usable from
     * the fault handler, where allocation (fopen/fprintf) is illegal. */
    fd = diag_crash_fd();
    if (fd >= 0) {
        write(fd, stamped, strlen(stamped));
    }
}
