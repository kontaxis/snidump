#ifndef __TLS_API_H__
#define __TLS_API_H__

/* kontaxis 2015-10-31 */

/* Register a callback function to the receive the value of the name field
 * in the ServerName extension of a TLS ClientHello handshake message.
 * (RFC4366 #3.1)
 */
int tls_set_callback_handshake_clienthello_servername(int (*handler)(
  uint8_t *host_name, uint16_t host_name_length));

/* Process the given payload as a TLS record. */
uint32_t tls_process_record(uint8_t *payload, uint32_t payload_length);

#endif
