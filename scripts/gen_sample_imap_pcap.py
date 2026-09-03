"""Second synthetic capture: STARTTLS offered AND used (client sends STARTTLS)."""
from scapy.all import IP, TCP, wrpcap
import time

client, server = "10.0.12.99", "198.51.100.77"
cport, sport = 52111, 143  # IMAP

pkts = []
seq_c, seq_s = 2000, 8000
t = time.time()

def add(src, dst, sport_, dport_, flags, seqn, ackn, payload=b""):
    global t
    t += 0.01
    pkt = IP(src=src, dst=dst) / TCP(sport=sport_, dport=dport_, flags=flags, seq=seqn, ack=ackn) / payload
    pkt.time = t
    pkts.append(pkt)

add(client, server, cport, sport, "S", seq_c, 0); seq_c += 1
add(server, client, sport, cport, "SA", seq_s, seq_c); seq_s += 1
add(client, server, cport, sport, "A", seq_c, seq_s)

banner = b"* OK IMAP4rev1 Service Ready\r\n"
add(server, client, sport, cport, "PA", seq_s, seq_c, banner); seq_s += len(banner)
add(client, server, cport, sport, "A", seq_c, seq_s)

cap = b"a1 CAPABILITY\r\n"
add(client, server, cport, sport, "PA", seq_c, seq_s, cap); seq_c += len(cap)
add(server, client, sport, cport, "A", seq_s, seq_c)

cap_resp = b"* CAPABILITY IMAP4rev1 STARTTLS\r\na1 OK CAPABILITY completed\r\n"
add(server, client, sport, cport, "PA", seq_s, seq_c, cap_resp); seq_s += len(cap_resp)
add(client, server, cport, sport, "A", seq_c, seq_s)

starttls = b"a2 STARTTLS\r\n"
add(client, server, cport, sport, "PA", seq_c, seq_s, starttls); seq_c += len(starttls)
add(server, client, sport, cport, "A", seq_s, seq_c)

starttls_resp = b"a2 OK Begin TLS negotiation now\r\n"
add(server, client, sport, cport, "PA", seq_s, seq_c, starttls_resp); seq_s += len(starttls_resp)
add(client, server, cport, sport, "A", seq_c, seq_s)

add(client, server, cport, sport, "FA", seq_c, seq_s); seq_c += 1
add(server, client, sport, cport, "FA", seq_s, seq_c); seq_s += 1
add(client, server, cport, sport, "A", seq_c, seq_s)

wrpcap("/home/claude/demo/data/sample_pcaps/imap_starttls_used.pcap", pkts)
print("wrote", len(pkts), "packets")
