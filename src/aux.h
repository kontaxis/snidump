#ifndef __AUX_H__
#define __AUX_H__

/* kontaxis 2015-10-31 */

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
	size_t must_read_bytes)
{
	if (!ctx) {
		return 0;
	}

	if (ctx->read_bytes_available < must_read_bytes) {
		return 0;
	}

	/* Reading must_read_bytes will cause an address overflow. */
	if (~((size_t)0x0) - (size_t) ctx->in < must_read_bytes) {
		return 0;
	}

	if (out != NULL) {
		memcpy(out, ctx->in, must_read_bytes);
	}
	ctx->in = ((uint8_t *) ctx->in) + must_read_bytes;

	ctx->read_bytes_available -= must_read_bytes;

	return must_read_bytes;
}

#endif
