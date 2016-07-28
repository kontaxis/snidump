# snidump
This program extracts the Server Name Indication (SNI) field from
TLS Handshake ClientHello messages (RFC 4366) as well as the Host
request-header field from HTTP/1.1 requests (RFC 2616).

It accepts as input either a network interface to monitor its traffic,
optionally in promiscuous mode, or a PCAP file to read from. By default
it uses a BPF to target TCP packets with destination port 80 or 443 but
it will handle TLS and HTTP packets on other ports as well as UDP packets
if configured accordingly. Captured traffic can be saved to a PCAP file.

If running as root, attempts to change to `nobody` user and `chroot` to
that user's home directory (`/var/empty` on some systems) after setting
up PCAP.

## Usage summary

```
Use: snidump [-h] [-f bpf] [-p] -i interface [-w dump.pcap]
Use: snidump [-h] [-f bpf] [-p] -r trce.pcap [-w dump.pcap]
```

## Capturing SNI traffic to a PCAP file

```
$ sudo bin/snidump -w test.pcap -i en0
Password:
1469712977.419406 [INFO] [*] PID: 66282
1469712977.419452 [INFO] [*] Device: 'en0'
1469712977.419455 [INFO] [*] Promiscuous: 0
1469712977.419785 [INFO] [*] BPF: 'ip and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and (dst port 80 or dst port 443)'
1469712977.419971 [INFO] [*] Dump: 'test.pcap'
1469712977.421253 [DEBUG] Dropped privileges: uid=-2, euid=-2, gid=-2, egid=-2
1469712977.423938 [INFO] Capturing ...
1469712985.430210 [INFO] 192.168.0.16:56842 -> 122.252.47.24:[443] 14:www.akamai.com
^C
1469712987.716071 [INFO] 2023 packets received
1469712987.716078 [INFO] 0 packets dropped
1469712987.716476 [INFO] Written test.pcap
1469712987.716482 [INFO] Goodbye
```

## Reading captured SNI traffic from a PCAP file

```
$ bin/snidump -r test.pcap
1469713000.327338 [INFO] [*] PID: 66677
1469713000.327365 [INFO] [*] Trace: 'test.pcap'
1469713000.327399 [INFO] [*] BPF: 'ip and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and (dst port 80 or dst port 443)'
1469713000.327570 [INFO] Capturing ...
1469713000.327595 [INFO] 192.168.0.16:56842 -> 122.252.47.24:[443] 14:www.akamai.com
1469713000.327632 [INFO] Goodbye
```
