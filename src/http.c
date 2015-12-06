/* kontaxis 2015-10-31 */

#include <stdio.h>
#include <stdint.h>

#include <pcre.h>

#include "http_api.h"

/* Regular expression to match an HTTP/1.1 request line. */
pcre       *pcre_HTTP_RequestLine;
pcre_extra *pcre_extra_HTTP_RequestLine;

/* Regular expression to match an HTTP/1.1 request Host header field. */
pcre       *pcre_HTTP_RequestHeaderHost;
pcre_extra *pcre_extra_HTTP_RequestHeaderHost;

void pcre_error_info(int r)
{
	if (r == 0) {
		fprintf(stderr, "%s/%s: Too many substrings found.\n",
			__FILE__, __func__);
		return;
	}

	switch(r) {
		case PCRE_ERROR_NOMATCH:
#if __DEBUG__
			fprintf(stderr, "%s:%s: No match.\n",
				__FILE__, __func__);
#endif
			break;
		case PCRE_ERROR_NULL:
			fprintf(stderr, "%s/%s: Something has null.\n",
				__FILE__, __func__);
			break;
		case PCRE_ERROR_BADOPTION:
			fprintf(stderr, "%s/%s: Bad option passed.\n",
				__FILE__, __func__);
			break;
		case PCRE_ERROR_BADMAGIC:
			fprintf(stderr, "%s/%s: Bad magic number.\n", __FILE__, __func__);
			break;
		case PCRE_ERROR_UNKNOWN_NODE:
			fprintf(stderr, "%s/%s: Compiled expression is faulty.\n",
				__FILE__, __func__);
			break;
		case PCRE_ERROR_NOMEMORY:
			fprintf(stderr, "%s/%s: Out of memory.\n", __FILE__, __func__);
			break;
		default:
			fprintf(stderr, "%s/%s: Unknown error.\n", __FILE__, __func__);
			break;
	}

	return;
}


int (*callback_request_host)(uint8_t *, uint16_t);

int http_set_callback_request_host(
  int (*handler)(uint8_t *, uint16_t))
{
  callback_request_host = handler;
  return 0;
}


/* Process the given payload as an HTTP request.
 *
 * Returns number of bytes processed.
 * - Zero indicates some parsing error. (Payload is not an HTTP request.)
 * - More than zero but less than payload_length indicates that an HTTP
 * request has been found with good confidence but there are trailing bytes
 * that we cannot make sense of.
 * - Exactly payload_length indicates with high confidence succesful parsing
 * of the entire payload as an HTTP request.
 *
 * Reference: https://tools.ietf.org/rfc/rfc2616.txt
 */
uint16_t http_process_request(uint8_t *payload, uint16_t payload_length)
{
	/* Holds the return value of pcre_exec. Used for reporting errors. */
	int r;
	/* pcre_exec offset vector. Supports up to two matching groups
	 * including the group for the whole expression.
	 */
	int ovector[6];

	/* Points to the beginning of the headers. */
	uint8_t *headers;
	uint16_t headers_length;

	/* Auxiliary variable. Used to iterate over payload bytes. */
	uint16_t i;

	/* Line ending with a CRLF. Extracted from payload. */
	uint8_t *line;
	uint16_t line_length;

	/* Make sure payload starts with a Request-Line. (RFC2616 #5.1) */
	r = pcre_exec(pcre_HTTP_RequestLine, NULL,
		(const char *)payload, payload_length, 0,
		0, ovector, sizeof(ovector)/sizeof(int));

	/* Error or no match. In any case we cannot proceed. */
	if (r <= 0) {
		pcre_error_info(r);
		return 0;
	}

	/* Match starts at ovector[0] and ends right before ovector[1].
	 * We will work on payload beyond the request line. */
	/* Check for address overflow. */
	if (SIZE_MAX - (size_t) payload < ovector[1] - ovector[0]) {
		return 0;
	}
	headers = payload + (ovector[1] - ovector[0]);
	headers_length = payload_length - (ovector[1] - ovector[0]);

	for (i = 0, line = headers; i < headers_length; i++) {
		/* The current line ends at the sequence \r\n. (RFC2616 #5) */
		if (headers[i] != '\n' || i == 0 || headers[i - 1] != '\r') {
			continue;
		}

		/* New line. Starts at line and has 'line_length' bytes. Including \r\n. */

		/* line_length = (line_end) - line + 1 */
		line_length = (headers + i) - line + 1;

		/* Empty line indicates the end of header fields. (RFC2616 #5)
		 * We stop processing immediately. This means that requests with a message
		 * body (e.g., POST requests) line - payload != payload_length which may
		 * produce a warning. This also means that we may miss additional requests
		 * in the same payload. TODO: Skip Content-Length bytes and look for a
		 * Request-Line followed by request headers.
		 */
		if (line_length == 2) {
			line += line_length;
			i += 1;
			break;
		}

		/* Match the current line against the Host request header field.
		 * (RFC2616 #5.3)
		 */
		r = pcre_exec(pcre_HTTP_RequestHeaderHost, NULL,
			(const char *)line, line_length, 0,
			0, ovector, sizeof(ovector)/sizeof(int));

		/* Error or no match. We move on to the next line. (if any) */
		if (r <= 0) {
			pcre_error_info(r);
			line += line_length;
			continue;
		}

		/* Match found starting at ovector[2] and ending right before ovector[3].
		 * We invoke the registered callback. (if any)
		 * We keep parsing the rest of the headers since there may be additional
		 * Host header fields in this request. (unlikely)
		 */
		if (callback_request_host != NULL) {
			callback_request_host(line + ovector[2], ovector[3] - ovector[2]);
		}

		line += line_length;
	}

	/* Return number of bytes processed. */
	return line - payload;
}


int http_init()
{
	const char *pcre_errptr;
	int         pcre_erroff;

	/*
	 * 5.1 Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
	 * https://tools.ietf.org/rfc/rfc2616.txt
	 */
	const char *regex_HTTP_RequestLine =
		"^(?:OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT) [^ ]+ HTTP/1\\.1\r\n";

	pcre_HTTP_RequestLine = pcre_compile(regex_HTTP_RequestLine, 0,
		&pcre_errptr, &pcre_erroff, NULL);

	if (pcre_errptr != NULL) {
		fprintf(stderr, "%s/%s: pcre_compile(%s): %s\n",
			__FILE__, __func__,
			regex_HTTP_RequestLine, pcre_errptr);
		return -1;
	}

	/* Optimize the regex. */
	pcre_extra_HTTP_RequestLine = pcre_study(pcre_HTTP_RequestLine, 0,
		&pcre_errptr);

	if (pcre_errptr != NULL) {
		fprintf(stderr, "%s/%s: pcre_study(%s): %s\n",
			__FILE__, __func__,
			regex_HTTP_RequestLine, pcre_errptr);
		return -1;
	}

	/*
	 * 14.23 Host = "Host" ":" host [ ":" port ] ; Section 3.2.2
	 * https://tools.ietf.org/rfc/rfc2616.txt
	 */
	const char *regex_HTTP_RequestHeaderHost = "^Host:[ ]*([^ ]+)[ ]*\r\n";

	if ((pcre_HTTP_RequestHeaderHost = pcre_compile(regex_HTTP_RequestHeaderHost,
		PCRE_CASELESS, &pcre_errptr, &pcre_erroff, NULL)) == NULL) {
		fprintf(stderr, "%s/%s: pcre_compile(%s): %s\n",
			__FILE__, __func__,
			regex_HTTP_RequestHeaderHost, pcre_errptr);
		return -1;
	}

	/* Optimize the regex. */
	pcre_extra_HTTP_RequestHeaderHost = pcre_study(pcre_HTTP_RequestHeaderHost,
		0, &pcre_errptr);

	if (pcre_errptr != NULL) {
		fprintf(stderr, "%s/%s: pcre_study(%s): %s\n",
			__FILE__, __func__,
			regex_HTTP_RequestHeaderHost, pcre_errptr);
		return -1;
	}

	return 0;
}


void http_cleanup()
{
	pcre_free(pcre_HTTP_RequestLine);
	if (pcre_extra_HTTP_RequestLine) {
		pcre_free(pcre_extra_HTTP_RequestLine);
	}

	pcre_free(pcre_HTTP_RequestHeaderHost);
	if (pcre_extra_HTTP_RequestHeaderHost) {
		pcre_free(pcre_extra_HTTP_RequestHeaderHost);
	}
}
