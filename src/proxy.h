/*
 * Remote PKG Installer NextGen
 * Copyright (c) 2025-present AldySan and contributors.
 * Licensed under the GNU General Public License v3.0. See LICENSE for details.
 *
 * Piece proxy: rewrites BGFT piece URLs to point at this app
 * (/static/proxy/<job>/<piece>) and streams each piece through the
 * adaptive prefetch engine, so downloads run at up to N-times
 * single-connection speed even against throttling origin servers.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Registers a job's pieces for proxying. Returns false on bad args or
 * registry exhaustion. urls/sizes are copied. */
bool proxy_register(int job_id, const char* const* urls,
                    const uint64_t* sizes, const bool* ranges_ok,
                    size_t count);

/*
 * Drops a job's proxy state. A live stream is aborted (its serving
 * connection owns it and frees it via proxy_stream_close); the piece
 * table is released.
 */
void proxy_unregister(int job_id);

/*
 * Opens a streaming handle for a piece. Prefetch acceleration is used
 * when the server supports Range requests and memory allows it; anything
 * else is served through a sequential single-request stream, so a valid
 * piece never fails to open. Connection count is chosen adaptively from
 * size + Range support. Only one piece streams per job at a time (BGFT
 * reads sequentially); opening a new piece aborts the previous one.
 */
/* Size of a registered piece, without opening anything (HEAD, Range checks).
 * Returns false when the job or piece is unknown. */
bool proxy_piece_size(int job_id, size_t piece, uint64_t* size);

/* Opens a stream over bytes [offset, offset + length) of a piece. Pass
 * offset 0 and the full size for a whole-piece request. A piece whose
 * origin ignores Range can only be streamed from offset 0. */
void* proxy_stream_open(int job_id, size_t piece, uint64_t offset,
                        uint64_t length);

/* How a stream is served, for diagnostics: "new" or "reuse" (the job's
 * read-ahead engine), "parallel" (single connection while the engine is
 * busy) or "direct" (origin without Range). A static string. */
const char* proxy_stream_mode(const void* stream);

/* Aborts every open stream and releases idle read-ahead engines, so the
 * connection threads serving them unwind at once (server shutdown, network
 * loss). Registrations stay; new requests can still open streams. */
void proxy_abort_all(void);

/* Waits until no stream is open and every prefetch engine has been freed
 * (its workers joined), up to timeout_ms. Returns false on timeout. */
bool proxy_wait_idle(int timeout_ms);

/* Streams currently open (diagnostics). */
int proxy_live_streams(void);

/* Reads the next block of the stream (0 at EOF, -1 on error). */
int64_t proxy_stream_read(void* stream, uint8_t* buf, size_t len);

/*
 * Frees a stream handle (its serving connection owns the stream).
 * job_id lets the registry drop its reference first, so a concurrent
 * piece change or unregister can never abort or double-free it.
 */
void proxy_stream_close(int job_id, void* stream);
