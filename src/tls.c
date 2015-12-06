/* kontaxis 2015-10-31 */

#include <stdio.h>
#include <time.h>

#include <arpa/inet.h>

#include <assert.h>

#include "tls.h"
#include "ciphersuites.h"

#include "aux.h"

#include "tls_api.h"

#include "colors.h"

void *tls_in;

int (*callback_handshake_clienthello_servername)(uint8_t *, uint16_t);

int tls_set_callback_handshake_clienthello_servername(
	int (*handler)(uint8_t *, uint16_t))
{
	callback_handshake_clienthello_servername = handler;
	return 0;
}

int tls_process_Handshake_ClientHello_Extensions_ServerName()
{
	size_t must_read_bytes;
	size_t must_read_name_list_bytes;

#if __DEBUG__
	unsigned int i;
#endif

	must_read_bytes = n16toh16(tls_Extension.extension_data_length);

	/* server_name_list_length */

	if (must_read_bytes <
		sizeof(tls_ServerNameList.server_name_list_length)) {
#if __DEBUG__
		fprintf(stderr,
			"Size of tls_ServerNameList.server_name_list_length is not expected.\n");
#endif
		return 0;
	}

	if (read_bytes(tls_in, &tls_ServerNameList.server_name_list_length,
		sizeof(tls_ServerNameList.server_name_list_length)) <= 0) {
#if __DEBUG__
		fprintf(stderr,
			"Not enough bytes for tls_ServerNameList.server_name_list_length.\n");
#endif
		return 0;
	}
	must_read_bytes -=
		sizeof(tls_ServerNameList.server_name_list_length);

#if __DEBUG__
	fprintf(stderr,
		"TLS ClientHello Extension SNI list length: %u\n",
		n16toh16(tls_ServerNameList.server_name_list_length));
#endif

	if (must_read_bytes <
		n16toh16(tls_ServerNameList.server_name_list_length)) {
#if __DEBUG__
		fprintf(stderr,
			"tls_ServerNameList.server_name_list_length is not expected.\n");
#endif
		return 0;
	}

	must_read_name_list_bytes = n16toh16(
		tls_ServerNameList.server_name_list_length);

	while (must_read_name_list_bytes > 0) {
		/* ServerName */

		/* name type */
		if (must_read_name_list_bytes < sizeof(tls_ServerName.name_type)) {
#if __DEBUG__
			fprintf(stderr, "Size of tls_ServerName.name_type is not expected.\n");
#endif
			return 0;
		}

		if (read_bytes(tls_in, &tls_ServerName.name_type,
			sizeof(tls_ServerName.name_type)) <= 0) {
#if __DEBUG__
			fprintf(stderr, "Not enough bytes for tls_ServerName.name_type.\n");
#endif
			return 0;
		}
		must_read_name_list_bytes -= sizeof(tls_ServerName.name_type);

#if __DEBUG__
	fprintf(stderr,
		"TLS ClientHello Extension SNI Type: (%u)\n", tls_ServerName.name_type);
#endif

		/* name length */
		if (must_read_name_list_bytes < sizeof(tls_ServerName.host_name_length)) {
#if __DEBUG__
			fprintf(stderr,
				"Size of tls_ServerName.host_name_length is not expected.\n");
#endif
			return 0;
		}

		if (read_bytes(tls_in, &tls_ServerName.host_name_length,
			sizeof(tls_ServerName.host_name_length)) <= 0) {
#if __DEBUG__
			fprintf(stderr,
				"Not enough bytes for tls_ServerName.host_name_length.\n");
#endif
			return 0;
		}
		must_read_name_list_bytes -= sizeof(tls_ServerName.host_name_length);

#if __DEBUG__
	fprintf(stderr,
		"TLS ClientHello Extension SNI length: %u\n",
		n16toh16(tls_ServerName.host_name_length));
#endif

		/* name */
		if (must_read_name_list_bytes <
			n16toh16(tls_ServerName.host_name_length)) {
#if __DEBUG__
			fprintf(stderr, "tls_ServerName.host_name_length is not expected.\n");
#endif
			return 0;
		}

		if (read_bytes(tls_in, &tls_ServerName.host_name,
			n16toh16(tls_ServerName.host_name_length)) <= 0) {
#if __DEBUG__
			fprintf(stderr, "Not enough bytes for tls_ServerName.host_name.\n");
#endif
			return 0;
		}
		must_read_name_list_bytes -= n16toh16(tls_ServerName.host_name_length);

#if __DEBUG__
		fprintf(stderr, "TLS ClientHello Extension SNI: ");
		for (i = 0; i < n16toh16(tls_ServerName.host_name_length); i++) {
			fprintf(stderr, "%c", tls_ServerName.host_name[i]);
		}
		fprintf(stderr, " (0x");
		for (i = 0; i < n16toh16(tls_ServerName.host_name_length); i++) {
			fprintf(stderr, "%02x", (uint8_t) tls_ServerName.host_name[i]);
		}
		fprintf(stderr, ")\n");
#endif

		if (callback_handshake_clienthello_servername != NULL) {
			callback_handshake_clienthello_servername(tls_ServerName.host_name,
				n16toh16(tls_ServerName.host_name_length));
		}
	} // must_read_name_list_bytes > 0
	must_read_bytes -= n16toh16(tls_ServerNameList.server_name_list_length);

	return n16toh16(tls_Extension.extension_data_length) - must_read_bytes;
}

int tls_process_Handshake_ClientHello_Extensions()
{
	size_t must_read_bytes;

	unsigned int r;

	/* Now we know we must read extensions_length bytes */

	must_read_bytes = n16toh16(tls_extensions.extensions_length);

	while (must_read_bytes > 0) {
		/* extension_type */

		if (must_read_bytes < sizeof(tls_Extension.extension_type)) {
#if __DEBUG__
			fprintf(stderr,
				"Size of tls_Extension.extension_type is not expected.\n");
#endif
			return 0;
		}

		if (read_bytes(tls_in, &tls_Extension.extension_type,
			sizeof(tls_Extension.extension_type)) <= 0) {
#if __DEBUG__
			fprintf(stderr, "Not enough bytes for tls_Extension.extension_type.\n");
#endif
			return 0;
		}
		must_read_bytes -= sizeof(tls_Extension.extension_type);

#if __DEBUG__
		fprintf(stderr, "TLS ClientHello Extension Type: %s (0x%04x)\n",
			TLS_EXTENSION_TXT(n16toh16(tls_Extension.extension_type)),
			n16toh16(tls_Extension.extension_type));
#endif

		/* extension_length */

		if (must_read_bytes <
			sizeof(tls_Extension.extension_data_length)) {
#if __DEBUG__
			fprintf(stderr,
				"Size of tls_Extension.extension_data_length is not expected.\n");
#endif
			return 0;
		}

		if (read_bytes(tls_in, &tls_Extension.extension_data_length,
			sizeof(tls_Extension.extension_data_length)) <= 0) {
#if __DEBUG__
			fprintf(stderr,
				"Not enough bytes for tls_Extension.extension_data_length.\n");
#endif
			return 0;
		}
		must_read_bytes -= sizeof(tls_Extension.extension_data_length);

#if __DEBUG__
		fprintf(stderr, "TLS ClientHello Extension Length: %u\n",
			n16toh16(tls_Extension.extension_data_length));
#endif

		if (must_read_bytes < n16toh16(tls_Extension.extension_data_length)) {
#if __DEBUG__
			fprintf(stderr,
				"tls_Extension.extension_data_length is not expected.\n");
#endif
			return 0;
		}

		/* extension */

		switch(n16toh16(tls_Extension.extension_type)) {
			case TLS_EXTENSION_TYPE_SERVER_NAME:
				if ((r =
					tls_process_Handshake_ClientHello_Extensions_ServerName()) == 0) {
					return r;
				}

				must_read_bytes -= r;
				break;

			default:
				if (read_bytes(tls_in, NULL,
					n16toh16(tls_Extension.extension_data_length)) <= 0 &&
					n16toh16(tls_Extension.extension_data_length) != 0) {
#if __DEBUG__
					fprintf(stderr, "Not enough bytes to match "
						"tls_Extension.extension_data_length.\n");
#endif
					return 0;
				}

				must_read_bytes -=
					n16toh16(tls_Extension.extension_data_length);
				break;
		} // tls_Extension.extension_type
	} // must_read_bytes > 0

	return n16toh16(tls_extensions.extensions_length);
}

/*
 * process a TLS Handshake ClientHello message
 */
int tls_process_Handshake_ClientHello()
{
#if __DEBUG__
	unsigned int i;
#endif

	unsigned int r;

	size_t must_read_bytes;

#if __DEBUG__
	time_t t;
	struct tm *ts;
	char time_buf[80];
#endif

	/* Exactly must_read_bytes bytes should follow in this ClientHello. */
	must_read_bytes = n24toh32(tls_Handshake_header.Handshake__length);

	/* client_version_major */
	/* client_version_minor */
	/* random_gmt_unix_time */
	/* random_random_bytes  */

	/* Read up to the session ID length byte. Since the session ID
	 * is of variable length we need to figure out how much to read as such. */
	if (must_read_bytes < sizeof(tls_ClientHello_intro)) {
#if __DEBUG__
		fprintf(stderr, "Size of tls_ClientHello_intro is not expected.\n");
#endif
		return 0;
	}

	if (read_bytes(tls_in, &tls_ClientHello_intro,
		sizeof(tls_ClientHello_intro)) <= 0) {
#if __DEBUG__
		fprintf(stderr, "Not enough bytes for ClientHello_intro.\n");
#endif
		return 0;
	}
	must_read_bytes -= sizeof(tls_ClientHello_intro);

#if __DEBUG__
	fprintf(stderr, "TLS ClientHello Version: %s (0x%02x%02x)\n",
		PROTOCOL_TXT(tls_ClientHello_intro.client_version_minor),
		tls_ClientHello_intro.client_version_major,
		tls_ClientHello_intro.client_version_minor);

	t = ntohl(tls_ClientHello_intro.random_gmt_unix_time);
	ts = localtime(&t);
	if (strftime(time_buf, sizeof(time_buf), "%b %d, %Y %H:%M:%S %Z", ts)) {
		fprintf(stderr, "TLS ClientHello Random gmt_unix_time: %s (%u)\n",
			time_buf, ntohl(tls_ClientHello_intro.random_gmt_unix_time));
	}

	fprintf(stderr, "TLS ClientHello Random random_bytes: ");
	for (i = 0; i < 28; i++)
		fprintf(stderr, "%02x", tls_ClientHello_intro.random_random_bytes[i]);
	fprintf(stderr, "\n");
#endif

	/* session_id_length */

	if (must_read_bytes < sizeof(tls_ClientHello_session.session_id_length)) {
#if __DEBUG__
		fprintf(stderr,
			"Size of tls_ClientHello_session.session_id_length is not expected.\n");
#endif
		return 0;
	}

	if (read_bytes(tls_in, &tls_ClientHello_session.session_id_length,
		sizeof(tls_ClientHello_session.session_id_length)) <= 0) {
#if __DEBUG__
			fprintf(stderr,
				"Not enough bytes for tls_ClientHello_session.session_id_length.\n");
#endif
		return 0;
	}
	must_read_bytes -= sizeof(tls_ClientHello_session.session_id_length);

#if __DEBUG__
	fprintf(stderr, "TLS ClientHello Session ID Length: %u\n",
		tls_ClientHello_session.session_id_length);
#endif

	if (must_read_bytes < tls_ClientHello_session.session_id_length) {
#if __DEBUG__
		fprintf(stderr,
			"tls_ClientHello_session.session_id_length is not expected.\n");
#endif
		return 0;
	}

	/* session_id */

	/* Now we know we must read session_id_length bytes */

	if (tls_ClientHello_session.session_id_length) {
		if (tls_ClientHello_session.session_id_length >
			sizeof(tls_ClientHello_session.session_id)) {
#if __DEBUG__
			fprintf(stderr,
				"Size of tls_ClientHello_session.session_id is not expected.\n");
#endif
			return 0;
		}

		if (read_bytes(tls_in, tls_ClientHello_session.session_id,
			tls_ClientHello_session.session_id_length) <= 0) {
#if __DEBUG__
			fprintf(stderr,
				"Not enough bytes to match tls_ClientHello_session.session_id.\n");
#endif
			return 0;
		}
		must_read_bytes -= tls_ClientHello_session.session_id_length;
	}

#if __DEBUG__
	for (i = 0; i < tls_ClientHello_session.session_id_length; i++) {
		if (i == 0) {
			fprintf(stderr, "TLS ClientHello Session ID: ");
		}
		fprintf(stderr, "%02x", tls_ClientHello_session.session_id[i]);
		if (i + 1 == tls_ClientHello_session.session_id_length) {
			fprintf(stderr, "\n");
		}
	}
#endif

	/* cipher_suites_length */

	if (must_read_bytes <
		sizeof(tls_ClientHello_ciphersuites.cipher_suites_length)) {
#if __DEBUG__
		fprintf(stderr,
			"Size of tls_ClientHello_ciphersuites.cipher_suites_length "
			"is not expected.\n");
#endif
		return 0;
	}

	if (read_bytes(tls_in, &tls_ClientHello_ciphersuites.cipher_suites_length,
		sizeof(tls_ClientHello_ciphersuites.cipher_suites_length)) <= 0) {
#if __DEBUG__
		fprintf(stderr, "Not enough bytes to match "
			"tls_ClientHello_ciphersuites.cipher_suites_length.\n");
#endif
		return 0;
	}
	must_read_bytes -= sizeof(tls_ClientHello_ciphersuites.cipher_suites_length);

#if __DEBUG__
	fprintf(stderr, "TLS ClientHello Cipher Suites Length: %u\n",
		n16toh16(tls_ClientHello_ciphersuites.cipher_suites_length));
#endif

	if (must_read_bytes <
		n16toh16(tls_ClientHello_ciphersuites.cipher_suites_length)) {
#if __DEBUG__
		fprintf(stderr, "tls_ClientHello_ciphersuites.cipher_suites_length "
			"is not expected.\n");
#endif
		return 0;
	}

	/* cipher_suites */

	if (n16toh16(tls_ClientHello_ciphersuites.cipher_suites_length) >
		sizeof(tls_ClientHello_ciphersuites.cipher_suites)) {
#if __DEBUG__
		fprintf(stderr, "Size of tls_ClientHello_ciphersuites.cipher_suites "
			"is not expected.\n");
#endif
		return 0;
	}

	if (read_bytes(tls_in, tls_ClientHello_ciphersuites.cipher_suites,
		n16toh16(tls_ClientHello_ciphersuites.cipher_suites_length)) <= 0) {
#if __DEBUG__
		fprintf(stderr,
			"Not enough bytes for tls_ClientHello_ciphersuites.cipher_suites.\n");
#endif
		return 0;
	}
	must_read_bytes -= n16toh16(
		tls_ClientHello_ciphersuites.cipher_suites_length);

#if __DEBUG__
	/* length is in bytes */
	for (i = 0;
		i < n16toh16(tls_ClientHello_ciphersuites.cipher_suites_length) /
			sizeof(CipherSuite); i++) {
		fprintf(stderr, "TLS ClientHello Cipher Suite: %s (0x%04x)\n",
			CIPHER_TXT(n16toh16(tls_ClientHello_ciphersuites.cipher_suites[i])),
			n16toh16(tls_ClientHello_ciphersuites.cipher_suites[i]));
	}
#endif

	/* compression_methods_length */

	if (must_read_bytes <
		sizeof(tls_ClientHello_compression.compression_methods_length)) {
#if __DEBUG__
		fprintf(stderr,
			"Size of tls_ClientHello_compression.compression_methods_length "
			"is not expected.\n");
#endif
		return 0;
	}

	if (read_bytes(tls_in,
		&tls_ClientHello_compression.compression_methods_length,
		sizeof(tls_ClientHello_compression.compression_methods_length)) <= 0) {
#if __DEBUG__
		fprintf(stderr, "Not enough bytes for "
			"tls_ClientHello_compression.compression_methods_length.\n");
#endif
		return 0;
	}
	must_read_bytes -=
		sizeof(tls_ClientHello_compression.compression_methods_length);

#if __DEBUG__
	fprintf(stderr, "TLS ClientHello Compression Methods Length: %u\n",
		tls_ClientHello_compression.compression_methods_length);
#endif

	if (must_read_bytes <
		tls_ClientHello_compression.compression_methods_length) {
#if __DEBUG__
		fprintf(stderr, "tls_ClientHello_compression.compression_methods_length "
			"is not expected.\n");
#endif
		return 0;
	}

	/* compression_methods */

	if (tls_ClientHello_compression.compression_methods_length >
		sizeof(tls_ClientHello_compression.compression_methods)) {
#if __DEBUG__
		fprintf(stderr, "Size of tls_ClientHello_compression.compression_methods "
			"is not expected.\n");
#endif
		return 0;
	}

	if (read_bytes(tls_in, tls_ClientHello_compression.compression_methods,
		tls_ClientHello_compression.compression_methods_length) <= 0) {
#if __DEBUG__
		fprintf(stderr, "Not enough bytes for "
			"tls_ClientHello_compression.compression_methods.\n");
#endif
		return 0;
	}
	must_read_bytes -= tls_ClientHello_compression.compression_methods_length;

#if __DEBUG__
	for (i = 0; i < tls_ClientHello_compression.compression_methods_length;
		i++) {
		fprintf(stderr, "TLS ClientHello Compression Method: %s (%u)\n",
			COMPRESSION_TXT(tls_ClientHello_compression.compression_methods[i]),
			tls_ClientHello_compression.compression_methods[i]);
	}
#endif

	/* tls_extensions */

	if (must_read_bytes > 0) {
		if (must_read_bytes < sizeof(tls_extensions.extensions_length)) {
#if __DEBUG__
			fprintf(stderr,
				"Size of tls_extensions.extensions_length is not expected.\n");
#endif
			return 0;
		}

		if (read_bytes(tls_in, &tls_extensions.extensions_length,
			sizeof(tls_extensions.extensions_length)) <= 0) {
#if __DEBUG__
			fprintf(stderr,
				"Not enough bytes for tls_extensions.extensions_length.\n");
#endif
			return 0;
		}
		must_read_bytes -= sizeof(tls_extensions.extensions_length);

#if __DEBUG__
		fprintf(stderr, "TLS ClientHello Extensions Length: %u\n",
			n16toh16(tls_extensions.extensions_length));
#endif

		if (must_read_bytes < n16toh16(tls_extensions.extensions_length)) {
#if __DEBUG__
			fprintf(stderr,
				"tls_extensions.tls_extensions_length is not expected.\n");
#endif
			return 0;
		}

		if ((r = tls_process_Handshake_ClientHello_Extensions()) == 0) {return r;}
		must_read_bytes -= r;
	} // must_read_bytes > 0

	return n24toh32(tls_Handshake_header.Handshake__length) - must_read_bytes;
}

/*
 * Processes an SSL/TLS Handshake.
 *
 * Returns number of bytes processed.
 * - Zero indicates some parsing error. (Payload is not a TLS record)
 * - More than zero but less than payload_length indicates than a TLS
 * record has been found with good confidence but there are trailing
 * bytes that we cannot make sense of.
 * - Exactly payload_length indicates with high confidence succesful parsing
 * of the entire payload as a TLS record.
 *
 */
uint32_t tls_process_record(uint8_t *payload, uint32_t payload_length)
{
	unsigned int r;

	size_t must_read_bytes;
	size_t read_bytes_checkpoint;

	struct read_bytes_ctx ctx;

	read_bytes_checkpoint = 0;

	/* Read context. */
	ctx.in = payload;
	ctx.read_bytes_available = payload_length;
	tls_in = &ctx;

	while (ctx.read_bytes_available > 0) {
		/* read SSL/TLS record header */
		if (read_bytes(tls_in, &tls_TLSPlaintext_header,
			sizeof(tls_TLSPlaintext_header)) <= 0) {
#if __DEBUG__
			fprintf(stderr, "Not enough bytes for tls_TLSPlaintext_header.\n");
#endif
			return read_bytes_checkpoint;
		}

#if __DEBUG__
		CPRINT_STDERR(C_BLUE_LIGHT, "[.] TLS Record "
			"type:%u(%s) version:%u.%u length:%u\n",
			tls_TLSPlaintext_header.TLSPlaintext__type,
			tls_ContentType(tls_TLSPlaintext_header.TLSPlaintext__type),
			tls_TLSPlaintext_header.TLSPlaintext__versionMajor,
			tls_TLSPlaintext_header.TLSPlaintext__versionMinor,
			n16toh16(tls_TLSPlaintext_header.TLSPlaintext__length));
#endif

		/* The record layer fragments information blocks (e.g., handshake
		 * messages or application data) into tls_TLSPlaintext records carrying
		 * data in chunks of 2^14 bytes or less.*/
		if (n16toh16(tls_TLSPlaintext_header.TLSPlaintext__length) > 0x4000) {
#if __DEBUG__
				fprintf(stderr, "TLSPlaintext__length > 0x4000.\n");
#endif
			return read_bytes_checkpoint;
		}

		/* Exactly must_read_bytes bytes should follow in this TLS record. */
		must_read_bytes = n16toh16(tls_TLSPlaintext_header.TLSPlaintext__length);

		if (ctx.read_bytes_available < must_read_bytes) {
#if __DEBUG__
			fprintf(stderr, "Not enough bytes to match TLSPlaintext__length.\n");
#endif
			return read_bytes_checkpoint;
		}

		/* process SSL/TLS record */
		switch(tls_TLSPlaintext_header.TLSPlaintext__type) {
			/* change_cipher_spec (20) */
			case SSL3_RT_CHANGE_CIPHER_SPEC:
				while (must_read_bytes > 0) {
					if (must_read_bytes < sizeof(tls_ChangeCipherSpec)) {
#if __DEBUG__
						fprintf(stderr, "Size of tls_ChangeCipherSpec is not expected.\n");
#endif
						return read_bytes_checkpoint;
					}

					if (read_bytes(tls_in, &tls_ChangeCipherSpec,
						sizeof(tls_ChangeCipherSpec)) <= 0) {
#if __DEBUG__
						fprintf(stderr, "Not enough bytes for tls_ChangeCipherSpec.\n");
#endif
						return read_bytes_checkpoint;
					}
					must_read_bytes -= sizeof(tls_ChangeCipherSpec);

#if __debug__
					CPRINT_STDERR(C_CYAN_LIGHT, "[.] TLS tls_ChangeCipherSpec\n");
#endif
				} // must_read_bytes > 0

				read_bytes_checkpoint = payload_length - ctx.read_bytes_available;
				break;

			/* alert (21) */
			case SSL3_RT_ALERT:
				while (must_read_bytes > 0) {
					if (must_read_bytes < sizeof(tls_Alert)) {
#if __DEBUG__
						fprintf(stderr, "Size of tls_Alert is not expected.\n");
#endif
						return read_bytes_checkpoint;
					}

					if (read_bytes(tls_in, &tls_Alert,
						sizeof(tls_Alert)) <= 0) {
#if __DEBUG__
						fprintf(stderr, "Not enough bytes for tls_Alert.\n");
#endif
						return read_bytes_checkpoint;
					}
					must_read_bytes -= sizeof(tls_Alert);

#if __DEBUG__
					CPRINT_STDERR(C_CYAN_LIGHT, "[.] TLS tls_Alert "
						"level:%u(%s) description:%u(%s)\n",
						tls_Alert.Alert__level,
						tls_AlertLevel(tls_Alert.Alert__level),
						tls_Alert.Alert__description,
						tls_AlertDescription(tls_Alert.Alert__description));
#endif

					switch(tls_Alert.Alert__level) {
						case SSL3_AL_WARNING:
						case SSL3_AL_FATAL:
							break;
						default:
#if __DEBUG__
							CPRINT_STDERR(C_RED_LIGHT,
								"[!] Unknown TLS Alert level:%u\n",
								tls_Alert.Alert__level);
#endif
							return read_bytes_checkpoint;
							break;
					} // tls_Alert.Alert__level

					switch(tls_Alert.Alert__description) {
						case SSL3_AD_CLOSE_NOTIFY:
						case SSL3_AD_UNEXPECTED_MESSAGE:
						case SSL3_AD_BAD_RECORD_MAC:
							break;
						default:
#if __DEBUG__
							CPRINT_STDERR(C_RED_LIGHT,
								"[!] Unknown TLS Alert description:%u\n",
								tls_Alert.Alert__description);
#endif
							return read_bytes_checkpoint;
							break;
					} // tls_Alert.Alert__description
				} // must_read_bytes > 0

				read_bytes_checkpoint = payload_length - ctx.read_bytes_available;
				break;

			/* handshake (22) */
			case SSL3_RT_HANDSHAKE:
				while (must_read_bytes > 0) {
					if (must_read_bytes < sizeof(tls_Handshake_header)) {
#if __DEBUG__
						fprintf(stderr, "Size of tls_Handshake_header is not expected.\n");
#endif
						return read_bytes_checkpoint;
					}

					/* read handshake header */
					if (read_bytes(tls_in, &tls_Handshake_header,
						sizeof(tls_Handshake_header)) <= 0) {
#if __DEBUG__
						fprintf(stderr, "Not enough bytes for tls_Handshake_header.\n");
#endif
						return read_bytes_checkpoint;
					}
					must_read_bytes -= sizeof(tls_Handshake_header);

#if __DEBUG__
					CPRINT_STDERR(C_CYAN_LIGHT,
						"[.] TLS Handshake "
						"type:%u(%s) length:%u\n",
						tls_Handshake_header.Handshake__type,
						tls_HandshakeType(tls_Handshake_header.Handshake__type),
						n24toh32(tls_Handshake_header.Handshake__length));
#endif

					if (must_read_bytes <
						n24toh32(tls_Handshake_header.Handshake__length)) {
#if __DEBUG__
						fprintf(stderr, "Not enough bytes to match Handshake__length.\n");
#endif
						return read_bytes_checkpoint;
					}

					/* process Handshake type */
					switch(tls_Handshake_header.Handshake__type) {
						/* ClientHello (1) */
						case SSL3_MT_CLIENT_HELLO:
							if ((r = tls_process_Handshake_ClientHello()) == 0) {
								return read_bytes_checkpoint;
							}

							must_read_bytes -= r;
							break;

						/* (0) */
						case SSL3_MT_HELLO_REQUEST:
							/* Fall through. */
						/* ServerHello (2) */
						case SSL3_MT_SERVER_HELLO:
							/* Fall through. */
						/* Certificate (11) */
						case SSL3_MT_CERTIFICATE:
							/* Fall through. */
						/* Server Key Exchange (12) */
						case SSL3_MT_SERVER_KEY_EXCHANGE:
							/* Fall through. */
						/* Certificate Request (13) */
						case SSL3_MT_CERTIFICATE_REQUEST:
							/* Fall through. */
						/* ServerHelloDone (14)*/
						case SSL3_MT_SERVER_DONE:
							/* Fall through. */
						/* (15) */
						case SSL3_MT_CERTIFICATE_VERIFY:
							/* Fall through. */
						/* (16) */
						case SSL3_MT_CLIENT_KEY_EXCHANGE:
							/* Fall through. */
						/* (20) */
						case SSL3_MT_FINISHED:
							/* consume (and ignore) rest of this record */
							if (read_bytes(tls_in, NULL,
									n24toh32(tls_Handshake_header.Handshake__length)) <= 0 &&
									n24toh32(tls_Handshake_header.Handshake__length) != 0) {
#if __DEBUG__
								fprintf(stderr,
									"Not enough bytes to match Handshake__length.\n");
#endif
								return read_bytes_checkpoint;
							}

							must_read_bytes -=
								n24toh32(tls_Handshake_header.Handshake__length);
							break;

						default:
#if __DEBUG__
							CPRINT_STDERR(C_RED_LIGHT,
								"[!] Unknown TLS handshake type:%u\n",
								(unsigned int) tls_Handshake_header.Handshake__type);

							for (r = 0; r < sizeof(tls_Handshake_header); r++) {
								fprintf(stderr, "0x%02x ",
									*(uint8_t *)(((uint8_t *)&tls_Handshake_header) + r));
							}
							fprintf(stderr, "\n");
#endif

							return read_bytes_checkpoint;
							break;
					} // tls_Handshake_header.Handshake__type
				} // must_read_bytes > 0

				read_bytes_checkpoint = payload_length - ctx.read_bytes_available;
				break;

			/* application_data (23) */
			case SSL3_RT_APPLICATION_DATA:
				if (read_bytes(tls_in, NULL,
					n16toh16(tls_TLSPlaintext_header.TLSPlaintext__length)) <= 0) {
#if __DEBUG__
					fprintf(stderr, "Not enough bytes to match TLSPlaintext__length.\n");
#endif
					return 0;
				}
				must_read_bytes = 0;

#if __DEBUG__
				CPRINT_STDERR(C_CYAN_LIGHT,
					"[.] TLS Application Data (%u)\n",
					n16toh16(tls_TLSPlaintext_header.TLSPlaintext__length));
#endif

				read_bytes_checkpoint = payload_length - ctx.read_bytes_available;
				break;

			default:
#if __DEBUG__
				CPRINT_STDERR(C_RED_LIGHT,
					"[!] Unknown TLS record type:%u\n",
					(unsigned int) tls_TLSPlaintext_header.TLSPlaintext__type);

				for (r = 0; r < sizeof(tls_TLSPlaintext_header); r++) {
					fprintf(stderr, "0x%02x ",
						*(uint8_t *)(((uint8_t *)&tls_TLSPlaintext_header) + r));
				}
				fprintf(stderr, "\n");
#endif

				return read_bytes_checkpoint;
				break;
		} // tls_TLSPlaintext_header.TLSPlaintext__type

		assert(must_read_bytes == 0);
	} // ctx.read_bytes_available > 0

	return read_bytes_checkpoint;
}
