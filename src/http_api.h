#ifndef __HTTP_API_H__
#define __HTTP_API_H__

/* kontaxis 2015-10-31 */

/* Register a callback function to receive the value of the Host header field
 * in an HTTP/1.1 request. (HTTP/1.1 RFC2616 #14.23)
 */
int http_set_callback_request_host(int (*handler)(
	uint8_t *host_name, uint16_t host_name_length));

/* Initialize the HTTP processing engine. */
int http_init();

/* Process the given payload as an HTTP request. */
uint16_t http_process_request(uint8_t *payload, uint16_t payload_length);

/* Clean up after the HTTP processing engine. */
void http_cleanup();

#endif
