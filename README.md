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

Note in the output that the log entries indicating a captured hostname 
display two timestamps; the first is the time the log message was
emitted, while the second timestamp (after the `[INFO]`) shows the
timestamp supplied by the PCAP library. This timestamp is stored in
the PCAP file if you choose to write one...
```
$ sudo bin/snidump -w test.pcap -i en0
Password:
1469715215.4996 [INFO] [*] PID: 74592
1469715215.5043 [INFO] [*] Device: 'en0'
1469715215.5046 [INFO] [*] Promiscuous: 0
1469715215.5431 [INFO] [*] BPF: 'ip and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and (dst port 80 or dst port 443)'
1469715215.5602 [INFO] [*] Dump: 'test.pcap'
1469715215.7336 [DEBUG] Dropped privileges: uid=-2, euid=-2, gid=-2, egid=-2
1469715215.10475 [INFO] Capturing ...
1469715227.19586 [INFO] 1469715226.726083 192.168.0.16:57547 -> 150.101.60.208:443 17:www.google.com.au
^C
1469715230.593574 [INFO] 2665 packets received
1469715230.593584 [INFO] 0 packets dropped
1469715230.593892 [INFO] Written test.pcap
1469715230.593900 [INFO] Goodbye
```


## Reading captured SNI traffic from a PCAP file

... So if you read back a PCAP file, you'll get the timestamps from
inside the file as well as the current time.

```
$ bin/snidump -r test.pcap
1469715244.402083 [INFO] [*] PID: 75167
1469715244.402123 [INFO] [*] Trace: 'test.pcap'
1469715244.402411 [INFO] [*] BPF: 'ip and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and (dst port 80 or dst port 443)'
1469715244.403574 [INFO] Reading ...
1469715244.404475 [INFO] 1469715226.726083 192.168.0.16:57547 -> 150.101.60.208:443 17:www.google.com.au
1469715244.404518 [INFO] Goodbye
```
