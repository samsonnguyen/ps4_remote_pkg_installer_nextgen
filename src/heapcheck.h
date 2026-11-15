/*
 * Remote PKG Installer NextGen
 * Copyright (c) 2025-present AldySan and contributors.
 * Licensed under the GNU General Public License v3.0. See LICENSE for details.
 *
 * Debug heap checker, compiled in only with `make DEBUG_HEAP=1`. Findings
 * (double free, overrun, write after free) go to /data/rpi_nextgen_heap.txt.
 */

#pragma once

#include <stddef.h>

#ifdef DEBUG_HEAP
/* Re-checks every quarantined freed block for writes after free. */
void heapcheck_scan(void);
/* One-line counters for the heartbeat journal. */
void heapcheck_stats(char* out, size_t outsz);
#else
static inline void heapcheck_scan(void) {}
static inline void heapcheck_stats(char* out, size_t outsz)
{
    if (out && outsz) {
        out[0] = '\0';
    }
}
#endif
