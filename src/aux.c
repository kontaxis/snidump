#include <sys/types.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aux.h"

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


void drop_privileges(void) {
  struct passwd* p;
  errno = 0;
  p = getpwnam("nobody");
  if (p == NULL) {
    log_fatal("can't lookup user 'nobody': %s",
      errno == 0 ? "probably doesn't exist" : strerror(errno));
  }
  if (chroot(p->pw_dir)) {
    log_fatal("chroot failed: %s", strerror(errno));
  }
  if (setgid(p->pw_gid) == -1) {
    log_fatal("setgid failed: %s", strerror(errno));
  }
  if (setuid(p->pw_uid) == -1) {
    log_fatal("setuid failed: %s", strerror(errno));
  }
  log_debug("Dropped privileges: uid=%d, euid=%d, gid=%d, egid=%d",
    getuid(), getgid(), geteuid(), getegid());
}

void log_message(FILE* file, int level, int newline, const char* fmt, ...) {
  va_list ap;
  struct timeval tv;

  const char* log_levels[] = { "FATAL", "WARN", "INFO", "DEBUG" };
  assert(file != NULL);
  assert(level >= LOG_FIRST);
  assert(level <= LOG_LAST);
  assert(fmt != NULL);
  if (gettimeofday(&tv,NULL)) {
    tv.tv_sec = tv.tv_usec = 0;
  }
  va_start(ap,fmt);
  fprintf(file, "%ld.%d [%s] ", tv.tv_sec, tv.tv_usec, log_levels[level]);
  vfprintf(file,fmt,ap);
  if (newline) {
    fputc('\n', file);
  }
  va_end(ap);
  if (level == LOG_FATAL) {
    exit(1);
  }
}

