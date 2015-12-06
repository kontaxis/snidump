# snidump
This program extracts the Server Name Indication (SNI) field from
TLS Handshake ClientHello messages (RFC 4366) as well as the Host
request-header field from HTTP/1.1 requests (RFC 2616).

It accepts as input either a network interface to monitor its traffic,
optionally in promiscuous mode, or a PCAP file to read from. By default
it uses a BPF to target TCP packets with destination port 80 or 443 but
it will handle TLS and HTTP packets on other ports as well as UDP packets
if configured accordingly. Captured traffic can be saved to a PCAP file.

```
Use: snidump [-h] [-f bpf] [-p] -i interface [-w dump.pcap]
Use: snidump [-h] [-f bpf] [-p] -r trce.pcap [-w dump.pcap]
```

```
# ./snidump -p -i eth0
[*] Device: 'eth0'
[*] Promiscuous: 1
[*] BPF: 'ip and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and (dst port 80 or dst port 443)'
Capturing ...
192.168.0.4:53072 -> 192.30.252.130:[443] 14:www.github.com
192.168.0.4:53073 -> 192.30.252.130:[443] 10:github.com
192.168.0.4:53074 -> 23.235.46.133:[443] 21:assets-cdn.github.com
192.168.0.4:53075 -> 23.235.46.133:[443] 21:assets-cdn.github.com
192.168.0.4:53076 -> 23.235.46.133:[443] 21:assets-cdn.github.com
192.168.0.4:53077 -> 23.235.46.133:[443] 21:assets-cdn.github.com
192.168.0.4:53080 -> 173.194.123.110:[443] 24:www.google-analytics.com
192.168.0.4:53081 -> 192.30.252.127:[443] 14:api.github.com
192.168.0.6:47232 -> 74.125.226.48:[80] 14:www.google.com
192.168.0.6:47233 -> 74.125.226.48:[443] 14:www.google.com
192.168.0.6:47234 -> 74.125.226.24:[443] 15:ssl.gstatic.com
192.168.0.6:47235 -> 74.125.226.48:[443] 14:www.google.com
192.168.0.6:47236 -> 74.125.226.5:[443] 15:apis.google.com

91 packets received
0 packets dropped
Goodbye
```
