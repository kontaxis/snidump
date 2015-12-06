#ifndef __TLS_H__
#define __TLS_H__

/* kontaxis 2015-10-31 */

#include "ciphersuites.h"

/* converts 16 bits in host byte order to 16 bits in network byte order */
#if !__BIG_ENDIAN__
#define h16ton16(n) \
((uint16_t) (((uint16_t) n) << 8) | (uint16_t) (((uint16_t) n) >> 8))
#else
#define h16ton16(n) (n)
#endif

#define n16toh16(buf) h16ton16(buf)

/* converts 24 bits in network byte order to 32 bits in host byte order */
#if !__BIG_ENDIAN__
#define n24toh32(buf) \
(((uint32_t) *(((uint8_t*)buf) + 0)) << 16 |\
 ((uint32_t) *(((uint8_t*)buf) + 1)) <<  8 |\
 ((uint32_t) *(((uint8_t*)buf) + 2)) <<  0)
#else
#define n24toh32(buf) \
(((uint32_t) *(((uint8_t*)buf) + 0)) >> 16 |\
 ((uint32_t) *(((uint8_t*)buf) + 1)) >>  8 |\
 ((uint32_t) *(((uint8_t*)buf) + 2)) >>  0)
#endif

/* convers 24 bits in host byte order to 32 bits in network byte order */
#if !__BIG_ENDIAN__
#define h24ton24(n,buf) \
{\
*(((uint8_t*)buf) + 0) = (uint8_t) (((uint32_t)n) >> 16);\
*(((uint8_t*)buf) + 1) = (uint8_t) (((uint32_t)n) >>  8);\
*(((uint8_t*)buf) + 2) = (uint8_t) (((uint32_t)n) >>  0);\
}
#else
#define h24ton24(n,buf) \
{\
*(((uint8_t*)buf) + 0) = (uint8_t) (((uint32_t)n) >>  0);\
*(((uint8_t*)buf) + 1) = (uint8_t) (((uint32_t)n) >>  8);\
*(((uint8_t*)buf) + 2) = (uint8_t) (((uint32_t)n) >> 16);\
}
#endif


/*
 * References:
 * - https://tools.ietf.org/html/rfc5246 TLS 1.2
 * - https://tools.ietf.org/html/rfc4346 TLS 1.1
 * - https://tools.ietf.org/html/rfc2246 TLS 1.0
 * - https://tools.ietf.org/html/rfc6101 SSL 3.0
 */

/* ContentType */
#define SSL3_RT_CHANGE_CIPHER_SPEC 20
#define SSL3_RT_ALERT              21
#define SSL3_RT_HANDSHAKE          22 /* 0x16 */
#define SSL3_RT_APPLICATION_DATA   23

struct __attribute__((__packed__))
{
	/* TLSPlaintext 5 bytes */
	uint8_t  TLSPlaintext__type; /* ContentType */
	uint8_t  TLSPlaintext__versionMajor;
	uint8_t  TLSPlaintext__versionMinor;
	uint16_t TLSPlaintext__length;
} tls_TLSPlaintext_header =
{
	.TLSPlaintext__versionMajor = PROTOCOLMAJOR,
	.TLSPlaintext__versionMinor = PROTOCOLMINOR
};

struct __attribute__((__packed__))
{
	uint8_t type;
} tls_ChangeCipherSpec;

/* AlertLevel */
#define SSL3_AL_WARNING 1
#define SSL3_AL_FATAL   2

/* AlertDescription */
#define SSL3_AD_CLOSE_NOTIFY        0
#define SSL3_AD_UNEXPECTED_MESSAGE 10
#define SSL3_AD_BAD_RECORD_MAC     20

struct __attribute__((__packed__))
{
	/* Alert 2 bytes */
	uint8_t Alert__level; /* AlertLevel */
	uint8_t Alert__description; /* AlertDescription */
} tls_Alert;

/* HandshakeType */
#define SSL3_MT_HELLO_REQUEST        0
#define SSL3_MT_CLIENT_HELLO         1
#define SSL3_MT_SERVER_HELLO         2
#define SSL3_MT_CERTIFICATE         11
#define SSL3_MT_SERVER_KEY_EXCHANGE 12
#define SSL3_MT_CERTIFICATE_REQUEST 13
#define SSL3_MT_SERVER_DONE         14
#define SSL3_MT_CERTIFICATE_VERIFY  15
#define SSL3_MT_CLIENT_KEY_EXCHANGE 16
#define SSL3_MT_FINISHED            20

struct __attribute__((__packed__))
{
	/* Handshake 4 bytes */
	uint8_t  Handshake__type; /* HandshakeType */
	uint8_t  Handshake__length[3];
} tls_Handshake_header;

/* ClientHello */

struct __attribute__((__packed__))
{
	uint8_t  client_version_major;
	uint8_t  client_version_minor;
	uint32_t random_gmt_unix_time;
	uint8_t  random_random_bytes[28];
} tls_ClientHello_intro =
{
	.client_version_major = PROTOCOLMAJOR,
	.client_version_minor = PROTOCOLMINOR
};

struct __attribute__((__packed__))
{
	uint8_t  session_id_length;
	uint8_t  session_id[32];
} tls_ClientHello_session =
{
	.session_id_length = 0
};

struct __attribute__((__packed__))
{
	uint16_t cipher_suites_length;
	uint16_t cipher_suites[(0xFFFF - 1)/sizeof(uint16_t)];
} tls_ClientHello_ciphersuites =
{
	.cipher_suites_length = 0x0200,
	.cipher_suites[0] = h16ton16(CIPHERSUITEMANDATORY)
};

struct __attribute__((__packed__))
{
	uint8_t compression_methods_length;
	uint8_t compression_methods[0xFF];
} tls_ClientHello_compression =
{
	.compression_methods_length = 0x1,
	.compression_methods[0] = 0x0
};

/* Smallest ClientHello */

struct __attribute__((__packed__))
{
	/* ClientHello 41 bytes */
	uint8_t  client_version_major;
	uint8_t  client_version_minor;
	uint32_t random_gmt_unix_time;
	uint8_t  random_random_bytes[28];
	uint8_t  session_id_length;
	uint16_t cipher_suites_length;
	uint16_t cipher_suites[1];
	uint8_t  compression_methods_length;
	uint8_t  compression_methods[1];
} tls_ClientHello_min =
{
	.session_id_length = 0,
	.cipher_suites_length = 0x0200,
	.compression_methods_length = 0x1
};

/* ServerHello */

struct __attribute__((__packed__))
{
	uint8_t  server_version_major;
	uint8_t  server_version_minor;
	uint32_t random_gmt_unix_time;
	uint8_t  random_random_bytes[28];
} tls_ServerHello_intro;

struct __attribute__((__packed__))
{
	uint8_t  session_id_length;
	uint8_t  session_id[32];
} tls_ServerHello_session;

struct __attribute__((__packed__))
{
	uint16_t cipher_suite;
} tls_ServerHello_ciphersuite;

struct __attribute__((__packed__))
{
	uint8_t compression_method;
} tls_ServerHello_compression;

/* Smallest ServerHello */

struct __attribute__((__packed__))
{
	/* ServerHello 38 bytes */
	uint8_t  server_version_major;
	uint8_t  server_version_minor;
	uint32_t random_gmt_unix_time;
	uint8_t  random_random_bytes[28];
	uint8_t  session_id_length;
	uint16_t cipher_suite;
	uint8_t  compression_method;
} tls_ServerHello_min =
{
	.session_id_length = 0
};

/* Extensions */

struct __attribute__((__packed__))
{
	uint16_t extensions_length;
	uint8_t  extensions[0xFFFF];
} tls_extensions;

struct __attribute__((__packed__))
{
	uint16_t extension_type;
	uint16_t extension_data_length;
	uint8_t  extension_data[0xFFFF];
} tls_Extension;

#define TLS_EXTENSIONS_MAX 0

const char * tls_ExtensionNames[TLS_EXTENSIONS_MAX + 1] = {
	/* https://tools.ietf.org/html/rfc3546 */
	"server_name", /* 0 */
};

#define TLS_EXTENSION_TXT(n) \
  (((n) >= 0 && (n) <= TLS_EXTENSIONS_MAX) ? tls_ExtensionNames[(n)] \
    : "UNKNOWN")

/*
 * Transport Layer Security (TLS) Extensions
 * https://tools.ietf.org/html/rfc3546
 */

/* server_name */

#define TLS_EXTENSION_TYPE_SERVER_NAME 0

struct __attribute__((__packed__))
{
	uint8_t  name_type;
	uint16_t host_name_length;
	uint8_t  host_name[0xFFFF];
} tls_ServerName;

struct __attribute__((__packed__))
{
	uint8_t  name_type;
	uint16_t host_name_length;
	uint8_t  host_name[1];
} tls_ServerName_min =
{
	.host_name_length = 1,
};

struct __attribute__((__packed__))
{
	uint16_t server_name_list_length;
	uint8_t  server_name_list[0xFFFF];
} tls_ServerNameList;

struct __attribute__((__packed__))
{
	uint16_t server_name_list_length;
	uint8_t  server_name_list[1];
} tls_ServerNameList_min =
{
	.server_name_list_length = 1,
};

/* Certificate */

struct __attribute__((__packed__))
{
	uint8_t certificate_length[3];
	uint8_t certificate[0xFFFFFF];
} tls_ASN1Cert;

/* Smallest ASN1 Certificate */

struct __attribute__((__packed__))
{
	uint8_t certificate_length[3];
	uint8_t certificate[1];
} tls_ASN1Cert_min =
{
	.certificate_length = {0x00, 0x00, 0x01}
};

struct __attribute__((__packed__))
{
	uint8_t certificate_list_length[3];
	uint8_t certificate_list[0xFFFFFF];
} tls_Certificate;

/* Smallest Certificate */

struct __attribute__((__packed__))
{
	uint8_t certificate_list_length[3];
} tls_Certificate_min =
{
	.certificate_list_length = {0x00, 0x00, 0x00}
};

/* Ephemeral DH parameters */

struct __attribute__((__packed__))
{
	uint16_t dh_p_length;
	uint8_t  dh_p[0xFFFF];
	uint16_t dh_g_length;
	uint8_t  dh_g[0xFFFF];
	uint16_t dh_Ys_length;
	uint8_t  dh_Ys[0xFFFF];
} tls_ServerDHParams;

/* Digital signature */

#define TLS_HASH_ALGORITHMS_MAX 6

const char * tls_HashAlgorithmNames[TLS_HASH_ALGORITHMS_MAX + 1] = {
	"none",   /* 0 */
	"md5",    /* 1 */
	"sha1",   /* 2 */
	"sha224", /* 3 */
	"sha256", /* 4 */
	"sha384", /* 5 */
	"sha512", /* 6 */
};

#define TLS_HASH_ALGORITHM_TXT(n) \
  (((n) >= 0 && (n) <= TLS_HASH_ALGORITHMS_MAX) ? \
		tls_HashAlgorithmNames[(n)] : "ERR_NOT_IMPLEMENTED")

#define TLS_SIGNATURE_ALGORITHMS_MAX 3

const char * tls_SignatureAlgorithmNames[TLS_SIGNATURE_ALGORITHMS_MAX + 1] = {
	"anonymous", /* 0 */
	"rsa",       /* 1 */
	"dsa",       /* 2 */
	"ecdsa",     /* 3 */
};

#define TLS_SIGNATURE_ALGORITHM_TXT(n) \
  (((n) >= 0 && (n) <= TLS_SIGNATURE_ALGORITHMS_MAX) ? \
		tls_SignatureAlgorithmNames[(n)] : "ERR_NOT_IMPLEMENTED")

struct __attribute__((__packed__))
{
	uint8_t  algorithm_hash;
	uint8_t  algorithm_signature;
	uint16_t signature_length;
	uint8_t  signature[0xFFFF];
} tls_DigitallySigned;

/*
 * struct {
 *   select (KeyExchangeAlgorithm) {
 *     case dh_anon:
 *       ServerDHParams params;
 *     case dhe_dss:
 *     case dhe_rsa:
 *       ServerDHParams params;
 *       digitally-signed struct {
 *         opaque client_random[32];
 *         opaque server_random[32];
 *         ServerDHParams params;
 *       } signed_params;
 *     case rsa:
 *     case dh_dss:
 *     case dh_rsa:
 *       struct {};
 *       // message is omitted for rsa, dh_dss, and dh_rsa
 *     // may be extended, e.g., for ECDH -- see [TLSECC]
 *   };
 * } ServerKeyExchange;
 */
struct __attribute__((__packed__)) {
	void *params;
	void *signed_params;
} tls_ServerKeyExchange;


/* Auxiliary decoding functions and utilities */

char *tls_ContentType(uint8_t n)
{
	switch (n) {
		/* 20*/
		case SSL3_RT_CHANGE_CIPHER_SPEC:
			return "change_cipher_spec";
		/* 21 */
		case SSL3_RT_ALERT:
			return "alert";
		/* 22 */
		case SSL3_RT_HANDSHAKE:
			return "handshake";
		/* 23 */
		case SSL3_RT_APPLICATION_DATA:
			return "application_data";
		default:
			return "UNKNOWN";
	}

	return "";
}

char *tls_AlertLevel(uint8_t n)
{
	switch(n) {
		/* 1 */
		case SSL3_AL_WARNING:
			return "warning";
		/* 2 */
		case SSL3_AL_FATAL:
			return "fatal";
		default:
			return "UNKNOWN";
	}

	return "";
}

char *tls_AlertDescription(uint8_t n)
{
	switch(n) {
		/* 0 */
		case SSL3_AD_CLOSE_NOTIFY:
			return "close_notify";
		/* 10 */
		case SSL3_AD_UNEXPECTED_MESSAGE:
			return "unexpected_message";
		/* 20 */
		case SSL3_AD_BAD_RECORD_MAC:
			return "bad_record_mac";
		case 21:
			return "decryption_failed_RESERVED";
		case 22:
			return "record_overflow";
		case 30:
			return "decompression_failure";
		case 40:
			return "handshake_failure";
		case 41:
			return "no_certificate_RESERVED";
		case 42:
			return "bad_certificate";
		case 43:
			return "unsupported_certificate";
		case 44:
			return "certificate_revoked";
		case 45:
			return "certificate_expired";
		case 46:
			return "certificate_unknown";
		case 47:
			return "illegal_parameter";
		case 48:
			return "unknown_ca";
		case 49:
			return "access_denied";
		case 50:
			return "decode_error";
		case 51:
			return "decrypt_error";
		default:
			return "UNKNOWN";
	}

	return "";
}

char *tls_HandshakeType(uint8_t n)
{
	switch(n) {
		/* 0 */
		case SSL3_MT_HELLO_REQUEST:
			return "hello_request";
		/* 1 */
		case SSL3_MT_CLIENT_HELLO:
			return "client_hello";
		/* 2 */
		case SSL3_MT_SERVER_HELLO:
			return "server_hello";
		/* 11 */
		case SSL3_MT_CERTIFICATE:
			return "certificate";
		/* 12 */
		case SSL3_MT_SERVER_KEY_EXCHANGE:
			return "server_key_exchange";
		/* 13 */
		case SSL3_MT_CERTIFICATE_REQUEST:
			return "certificate_request";
		/* 14 */
		case SSL3_MT_SERVER_DONE:
			return "server_hello_done";
		/* 15 */
		case SSL3_MT_CERTIFICATE_VERIFY:
			return "certificate_verify";
		/* 16 */
		case SSL3_MT_CLIENT_KEY_EXCHANGE:
			return "client_key_exchange";
		/* 20 */
		case SSL3_MT_FINISHED:
			return "finished";
		default:
			return "UNKNOWN";
	}

	return "";
}

#endif
