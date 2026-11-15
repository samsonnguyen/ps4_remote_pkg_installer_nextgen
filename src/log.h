/*
 * Remote PKG Installer NextGen
 * Copyright (c) 2025-present AldySan and contributors.
 * Licensed under the GNU General Public License v3.0. See LICENSE for details.
 *
 * Logging facade: stdout (kernel log) + dbglogger (UDP/file sink) + an
 * in-memory ring buffer served by the v2 API and shown on the dashboard.
 */
#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <dbglogger.h>

/* Ring buffer sink (fixed size, no allocation; safe from any thread). */
#define LOG_RING_CAPACITY 64
#define LOG_RING_ENTRY_MAX 200

void log_ring_add(const char* level, const char* fmt, ...);

/* Copies the entry at index (0 = oldest) into out; false when exhausted.
 * Use log_ring_count() for iteration. */
bool log_ring_get(int index, char* out, size_t outsz);
int log_ring_count(void);

/*
 * One serialized write to stdout + dbglogger, then the ring. Use this (via
 * the LOG_* macros) instead of printf: stdio does no locking in this app
 * (see logring.c), so unsynchronized printf from several threads corrupts
 * memory.
 */
void log_emit(const char* level, const char* fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Stops the stdout/dbglogger sinks (exit); later logs reach only the ring. */
void log_sinks_close(void);

#define LOG_INFO(...)  log_emit("INFO", __VA_ARGS__)
#define LOG_WARN(...)  log_emit("WARN", __VA_ARGS__)
#define LOG_ERROR(...) log_emit("ERROR", __VA_ARGS__)
#define LOG_DEBUG(...) log_emit("DEBUG", __VA_ARGS__)
