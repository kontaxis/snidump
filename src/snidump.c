/* kontaxis 2015-10-31 */

#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap/pcap.h>
#include <pcre.h>

#if !__DEBUG__
#define NDEBUG
#endif
#include <assert.h>

#include "tls_api.h"
#include "http_api.h"

#include "colors.h"
uint8_t istty_stdout;
uint8_t istty_stderr;

/* References:
 *   netinet/ether.h
 *   netinet/ip.h
 *   netinet/tcp.h
 *   netinet/udp.h
 */

/* Ethernet */

#define ETH_ALEN 6

struct ether_header
{
  uint8_t  ether_dhost[ETH_ALEN];
  uint8_t  ether_shost[ETH_ALEN];
  uint16_t ether_type;
} __attribute__ ((__packed__));

#define ETHERTYPE_IP 0x0800 /* IP */

#if !__NO_ETHERNET__
#define SIZE_ETHERNET sizeof(struct ether_header)
#else
#define SIZE_ETHERNET 0
#endif

/* IP */

struct my_iphdr
{
  uint8_t  vhl;
#define IP_HL(ip) (((ip)->vhl) & 0x0F)
#define IP_V(ip)  (((ip)->vhl) >> 4)
  uint8_t  tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
  /*The options start here. */
} __attribute__ ((__packed__));

#define MIN_SIZE_IP (sizeof(struct my_iphdr))
#define MAX_SIZE_IP (0xF * sizeof(uint32_t))

#define IPVERSION 4

#define IPPROTO_TCP  6
#define IPPROTO_UDP 17

/* TCP */

struct my_tcphdr
{
  uint16_t source;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
  uint8_t  res1doff;
#define TCP_OFF(th)      (((th)->res1doff & 0xF0) >> 4)
	uint8_t  flags;
#define TCP_FIN  (0x1 << 0)
#define TCP_SYN  (0x1 << 1)
#define TCP_RST  (0x1 << 2)
#define TCP_PUSH (0x1 << 3)
#define TCP_ACK  (0x1 << 4)
#define TCP_URG  (0x1 << 5)
#define TCP_ECE  (0x1 << 6)
#define TCP_CWR  (0x1 << 7)
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
} __attribute__ ((__packed__));

#define MIN_SIZE_TCP (sizeof(struct my_tcphdr))
#define MAX_SIZE_TCP (0xF * sizeof(uint32_t))

/* UDP */

struct udphdr
{
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
} __attribute__ ((__packed__));

#define MIN_SIZE_UDP (sizeof(struct udphdr))


/* converts 16 bits in host byte order to 16 bits in network byte order */
#if !__BIG_ENDIAN__
#define h16ton16(n) \
((uint16_t) (((uint16_t) n) << 8) | (uint16_t) (((uint16_t) n) >> 8))
#else
#define h16ton16(n) (n)
#endif

#define n16toh16(n) h16ton16(n)

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)


pcap_t *pcap_handle;
pcap_dumper_t * pcap_dumper_handle;


struct my_iphdr *ip;

uint16_t src_port;
uint16_t dst_port;


uint8_t flag_sni_available;

int sni_handler (uint8_t *host_name, uint16_t host_name_length) {
	uint16_t i;

	fprintf(stdout, "%u.%u.%u.%u:%u -> %u.%u.%u.%u:[%u] ",
		*(((uint8_t *)&(ip->saddr)) + 0),
		*(((uint8_t *)&(ip->saddr)) + 1),
		*(((uint8_t *)&(ip->saddr)) + 2),
		*(((uint8_t *)&(ip->saddr)) + 3),
		n16toh16(src_port),
		*(((uint8_t *)&(ip->daddr)) + 0),
		*(((uint8_t *)&(ip->daddr)) + 1),
		*(((uint8_t *)&(ip->daddr)) + 2),
		*(((uint8_t *)&(ip->daddr)) + 3),
		n16toh16(dst_port));


	CPRINT_STDOUT(C_RED_LIGHT, "%u:", host_name_length);
	for (i = 0; i < host_name_length; i++) {
		CPRINT_STDOUT(C_RED_LIGHT, "%c", host_name[i]);
	}
	fprintf(stdout, "\n");

	flag_sni_available = 1;

	return 0;
}


void my_pcap_handler (uint8_t *user, const struct pcap_pkthdr *header,
	const uint8_t *packet)
{
#if !__NO_ETHERNET__
	struct ether_header *ether;
#endif
	struct my_tcphdr *tcp;
	struct udphdr *udp;

	uint8_t *payload;
	uint16_t payload_length;

	uint16_t r;

	if (header->caplen < header->len) {
#if __DEBUG__
		fprintf(stderr,
			"WARNING: caplen %u < len %u. Ignoring.\n",
			header->caplen, header->len);
#endif
		return;
	}

#if !__NO_ETHERNET__
	/* Process ethernet header */
	assert(header->caplen >= SIZE_ETHERNET);

	ether = (struct ether_header *) packet;
	if (unlikely(ether->ether_type != h16ton16(ETHERTYPE_IP))) {
#if __DEBUG__
		fprintf(stderr,
			"WARNING: ether->ether_type != ETHERTYPE_IP. Ignoring.\n");
#endif
		return;
	}
#endif

	/* Process IP header */
	assert(header->caplen >= SIZE_ETHERNET + MIN_SIZE_IP);

	ip = (struct my_iphdr *) (packet + SIZE_ETHERNET);
	if (unlikely(IP_V(ip) != IPVERSION)) {
#if __DEBUG__
		fprintf(stderr, "WARNING: IP_V(ip) != 4. Ignoring.\n");
#endif
		return;
	}

	switch(ip->protocol) {
		case IPPROTO_TCP: {
				/* Process TCP header */
				assert(header->caplen >=
					SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)) + MIN_SIZE_TCP);

				tcp = (struct my_tcphdr *)
					(packet + SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)));
				src_port = tcp->source;
				dst_port = tcp->dest;

				/* Make sure we have captured the entire packet. */
				assert(header->caplen >= SIZE_ETHERNET +
					(IP_HL(ip) * sizeof(uint32_t)) + (TCP_OFF(tcp) * sizeof(uint32_t)));

				/* Figure out payload. */
				payload = (uint8_t *)
					(packet + SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)) +
					(TCP_OFF(tcp) * sizeof(uint32_t)));
				payload_length = header->caplen - SIZE_ETHERNET -
					(IP_HL(ip) * sizeof(uint32_t)) - (TCP_OFF(tcp) * sizeof(uint32_t));
			}
			break;
		case IPPROTO_UDP: {
				/* Process UDP header */
				assert(header->caplen >=
					SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)) + MIN_SIZE_UDP);
				udp = (struct udphdr *)
					(packet + SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)));
				src_port = udp->source;
				dst_port = udp->dest;

				/* Make sure we have captured the entire packet. */
				assert(header->caplen >= SIZE_ETHERNET +
					(IP_HL(ip) * sizeof(uint32_t)) + sizeof(struct udphdr));

				/* Figure out payload. */
				payload = (uint8_t *)
					(packet + SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)) +
					sizeof(struct udphdr));
				payload_length = header->caplen - SIZE_ETHERNET -
					(IP_HL(ip) * sizeof(uint32_t)) - sizeof(struct udphdr);
			}
			break;
		default:
				src_port = 0;
				dst_port = 0;
				payload = NULL;
				payload_length = 0;
#if __DEBUG__
			fprintf(stderr, "WARNING: ip->protocol == %u. Ignoring.\n",
				ip->protocol);
#endif
			break;
	}

	/* Save to dump file. */
	if (pcap_dumper_handle) {
		pcap_dump((u_char *)pcap_dumper_handle, header, packet);
	}

#if __DEBUG__
	fprintf(stderr, "%u.%u.%u.%u:%u -> %u.%u.%u.%u:[%u] (payload:%u)\n",
		*(((uint8_t *)&(ip->saddr)) + 0),
		*(((uint8_t *)&(ip->saddr)) + 1),
		*(((uint8_t *)&(ip->saddr)) + 2),
		*(((uint8_t *)&(ip->saddr)) + 3),
		n16toh16(src_port),
		*(((uint8_t *)&(ip->daddr)) + 0),
		*(((uint8_t *)&(ip->daddr)) + 1),
		*(((uint8_t *)&(ip->daddr)) + 2),
		*(((uint8_t *)&(ip->daddr)) + 3),
		n16toh16(dst_port),
		payload_length);
#endif

	if (payload_length == 0 || payload == NULL) {
		return;
	}

	/* Reset flag_sni_available. If it is set following any of the processing
	 * engines we know we have found the server's name and we can stop.
	 */
	flag_sni_available = 0;

	r = tls_process_record(payload, payload_length);
#if __DEBUG__
	/* It's not ideal to have bytes left unprocessed by the engine.
	 * This is usually because of fragmented application messages.
	 * (e.g., a TLS handshake record spread across packets)
	 */
	if (r < payload_length) {
		fprintf(stderr, "process_TLS_record() processed %u / %u bytes.\n",
			r, payload_length);
	}
#endif
	/* If flag_sni_available then we have done. */
	/* If we have processed more than zero bytes then we are (probably) done. */
	if (flag_sni_available || r != 0) {
		return;
	}

	r = http_process_request(payload, payload_length);
#if __DEBUG__
	if (r < payload_length) {
		fprintf(stderr, "http_process_request() processed %u / %u bytes.\n",
			r, payload_length);
	}
#endif
	if (flag_sni_available || r != 0) {
		return;
	}

	return;
}


void signal_handler (int signum)
{
	switch(signum) {
		case SIGTERM:
		case SIGINT:
		case SIGSEGV:
			fprintf(stdout, "\n");
			pcap_breakloop(pcap_handle);
			break;
		default:
			break;
	}
}

#define SNAPLEN 65535
#define PROMISCUOUS ((opt_flags & OPT_PROMISCUOUS) == OPT_PROMISCUOUS)
#define PCAP_TIMEOUT 1000

#define BPF_DEFAULT \
	"ip and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and " \
	"(dst port 80 or dst port 443)"
#define BPF bpf_s
#define BPF_OPTIMIZE 1

int main (int argc, char *argv[])
{
	/* Name of the network interface to capture from. */
	char *device_name;
	/* Name of the file with the pcap trace to read from. */
	char *trace_fname;

	char errbuf[PCAP_ERRBUF_SIZE];

	char *bpf_s;
	char *bpf_default = BPF_DEFAULT;
	struct bpf_program bpf;

	/* Name of the file to write the pcap trace to. */
	char *dump_fname;
#if __DEBUG__
	unsigned int dump_fname_sz;
#endif

	struct pcap_stat ps;

	struct sigaction act;

	int i;
#define OPT_DEVICE      (0x1 << 0)
#define OPT_PROMISCUOUS (0x1 << 1)
#define OPT_BPF         (0x1 << 2)
#define OPT_TRACE       (0x1 << 3)
#define OPT_DUMP        (0x1 << 4)
	uint8_t opt_flags;

	opt_flags = 0;

	memset(errbuf, 0, PCAP_ERRBUF_SIZE);

	CPRINT_INIT

	while ((i = getopt(argc, argv, "hf:pi:r:w:")) != -1) {
		switch(i) {
			case 'h':
				fprintf(stderr,
					"Use: %s [-h] [-f bpf] [-p] -i interface [-w dump.pcap]\n", argv[0]);
				fprintf(stderr,
					"Use: %s [-h] [-f bpf] [-p] -r trce.pcap [-w dump.pcap]\n", argv[0]);
				return -1;
				break;
			case 'f':
				bpf_s = optarg;
				opt_flags |= OPT_BPF;
				break;
			case 'p':
				opt_flags |= OPT_PROMISCUOUS;
				break;
			case 'i':
				device_name = optarg;
				opt_flags |= OPT_DEVICE;
				break;
			case 'r':
				trace_fname = optarg;
				opt_flags |= OPT_TRACE;
				break;
			case 'w':
				dump_fname = optarg;
				opt_flags |= OPT_DUMP;
				break;
			default:
				break;
		}
	}

	if (!(opt_flags & (OPT_DEVICE | OPT_TRACE))) {
		fprintf(stderr,
			"[FATAL] Missing target interface or trace file. Try with -h.\n");
		return -1;
	}

#if __DEBUG__
#if !__BIG_ENDIAN__
	fprintf(stderr, "LITTLE_ENDIAN\n");
#else
	fprintf(stderr, "BIG_ENDIAN\n");
#endif
#endif

	fprintf(stdout, "[*] PID: %u\n", getpid());

	if (opt_flags & OPT_DEVICE) {
		fprintf(stdout, "[*] Device: '%s'\n", device_name);
		fprintf(stdout, "[*] Promiscuous: %d\n", PROMISCUOUS);

		if (!(pcap_handle =
			pcap_open_live(device_name, SNAPLEN, PROMISCUOUS, PCAP_TIMEOUT,
			errbuf))) {
			fprintf(stderr, "[FATAL] %s\n", errbuf);
			return -1;
		}
	}

	if (opt_flags & OPT_TRACE) {
		fprintf(stdout, "[*] Trace: '%s'\n", trace_fname);

		if (!(pcap_handle =
			pcap_open_offline(trace_fname, errbuf))) {
			fprintf(stderr, "[FATAL] %s\n", errbuf);
			return -1;
		}
	}

	/* BPF is not set. We'll use the default. */
	if (!(opt_flags & OPT_BPF)) {
		bpf_s = bpf_default;
		opt_flags |= OPT_BPF;
	}

	fprintf(stdout, "[*] BPF: '%s'\n", bpf_s);

	if (pcap_compile(pcap_handle, &bpf, BPF, BPF_OPTIMIZE,
		PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "[FATAL] Couldn't parse filter. %s\n",
			pcap_geterr(pcap_handle));
		pcap_close(pcap_handle);
		return -1;
	}

	if (pcap_setfilter(pcap_handle, &bpf) == -1) {
		fprintf(stderr, "[FATAL] Couldn't install filter. %s\n",
			pcap_geterr(pcap_handle));
		pcap_close(pcap_handle);
		return -1;
	}

	pcap_freecode(&bpf);

	pcap_dumper_handle = NULL;

	if (opt_flags & OPT_DUMP) {
		fprintf(stdout, "[*] Dump: '%s'\n", dump_fname);

		if (!(pcap_dumper_handle = pcap_dump_open(pcap_handle, dump_fname))) {
			fprintf(stderr, "[WARNING] Couldn't create dump file. %s\n",
				pcap_geterr(pcap_handle));
		}
	}

#if __DEBUG__
	if ((!(opt_flags & OPT_DUMP)) && (opt_flags & OPT_DEVICE)) {
		dump_fname_sz = strlen(device_name) + strlen(".pcap") + 1;
		if ((dump_fname = malloc(sizeof(char) * dump_fname_sz)) == NULL) {
			perror("malloc");
			return -1;
		}
		snprintf(dump_fname, dump_fname_sz, "%s%s", device_name, ".pcap");
		if (!(pcap_dumper_handle = pcap_dump_open(pcap_handle, dump_fname))) {
			pcap_geterr(pcap_handle);
		}
	}
#endif

	tls_set_callback_handshake_clienthello_servername(&sni_handler);
	http_set_callback_request_host(&sni_handler);

	http_init();

	act.sa_handler = signal_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;

	if (sigaction(SIGINT, &act, NULL)) {
		perror("sigaction");
		fprintf(stderr,
			"[WARNING] Failed to set signal handler for SIGINT.\n");
	}

	if (sigaction(SIGTERM, &act, NULL)) {
		perror("sigaction");
		fprintf(stderr,
			"[WARNING] Failed to set signal handler for SIGTERM.\n");
	}

	if (sigaction(SIGSEGV, &act, NULL)) {
		perror("sigaction");
		fprintf(stderr,
			"[WARNING] Failed to set signal handler for SIGSEGV.\n");
	}

	fprintf(stderr, "Capturing ...\n");

	if (pcap_loop(pcap_handle, -1, &my_pcap_handler, NULL) == -1) {
		fprintf(stderr, "[FATAL] pcap_loop failed. %s\n",
			pcap_geterr(pcap_handle));
	}

	if (!(opt_flags & OPT_TRACE)) {
		if (pcap_stats(pcap_handle, &ps) == -1) {
			fprintf(stderr, "pcap_stats failed. %s\n", pcap_geterr(pcap_handle));
		} else {
			fprintf(stderr, "%u packets received\n", ps.ps_recv);
			fprintf(stderr, "%u packets dropped\n", ps.ps_drop + ps.ps_ifdrop);
		}
	}

	pcap_close(pcap_handle);

	http_cleanup();

	if (pcap_dumper_handle) {
		pcap_dump_close(pcap_dumper_handle);

		fprintf(stderr, "Written %s\n", dump_fname);
		if (!(opt_flags & OPT_DUMP)) {
			free(dump_fname);
		}
	}

	fprintf(stderr, "Goodbye\n");

	return 0;
}
