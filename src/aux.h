#ifndef __AUX_H__
#define __AUX_H__

/* kontaxis 2015-10-31 */

#include <stdio.h>
#include <string.h>
#include <limits.h>

struct read_bytes_ctx {
	/* Buffer holding data to be read. */
	void *in;
	/* MUST be set to the exact number of bytes available in the 'in' buffer
	 * BEFORE the first call to read_bytes() is moade.
	 */
	size_t read_bytes_available;
};

/*
 * Copies exactly 'must_read_bytes' bytes from 'ctx->in' to 'out' or fails.
 *
 * If 'out' is NULL nothing is copied but the read_bytes_available variable
 * is incremented by must_read_bytes bytes.
 *
 * Returns number of bytes copied.
 * - 'must_read_bytes' bytes indicate success.
 * -                 0 bytes indicate failure.
 */
size_t read_bytes(struct read_bytes_ctx *ctx, void *out,
	size_t must_read_bytes);

#define LOG_FATAL 0
#define LOG_WARN  1
#define LOG_INFO  2
#define LOG_DEBUG 3
#define LOG_LAST  LOG_DEBUG
#define LOG_FIRST LOG_FATAL
#define log_fatal(...) log_message(stderr,LOG_FATAL,1,__VA_ARGS__)
#define log_warn(...)  log_message(stderr,LOG_WARN,1,__VA_ARGS__)
#define log_info(...)  log_message(stdout,LOG_INFO,1,__VA_ARGS__)
#define log_debug(...) log_message(stdout,LOG_DEBUG,1,__VA_ARGS__)
#define log_info_nonl(...)  log_message(stdout,LOG_INFO,0,__VA_ARGS__)
#define log_debug_nonl(...) log_message(stdout,LOG_DEBUG,0,__VA_ARGS__)
void log_message(FILE* file, int level, int newline, const char* fmt, ...);
void drop_privileges(void);

#endif
