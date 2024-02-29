#ifndef __COLORS_H__
#define __COLORS_H__

#include <stdio.h>
#include <unistd.h>

#define IFTTY_STDOUT(x) (istty_stdout ? (x) : "")
static uint8_t istty_stdout;

#define IFTTY_STDERR(x) (istty_stderr ? (x) : "")
static uint8_t istty_stderr;

#define C_RED_LIGHT    "1;31"
#define C_GREEN_LIGHT  "1;32"
#define C_BLUE_LIGHT   "1;34"
#define C_PURPLE_LIGHT "1;35"
#define C_CYAN_LIGHT   "1;36"

/* Must be called at least once to determine where stdout, stderr refer to. */
#define CPRINT_INIT {\
	istty_stdout = isatty(STDOUT_FILENO); \
	istty_stderr = isatty(STDERR_FILENO); \
}

/* Wraps around fprintf and adds prefix \033[X;YZm as well as suffix \033[0m
 * to its format string if stdout refers to a terminal and not a pipe.
 * X:YZ is a C_ color as defined above.
 */
#define CPRINT_STDOUT(color, format, ...) fprintf(stdout, "%s" format "%s", \
  IFTTY_STDOUT("\033[" color "m"), __VA_ARGS__, IFTTY_STDOUT("\033[0m"))

#define CPRINT_STDERR(color, format, ...) fprintf(stderr, "%s" format "%s", \
  IFTTY_STDERR("\033[" color "m"), __VA_ARGS__, IFTTY_STDERR("\033[0m"))

#endif
