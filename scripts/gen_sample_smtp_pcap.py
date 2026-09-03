"""
Builds a synthetic PCAP of a plaintext SMTP session that offers STARTTLS
but never upgrades -- exercises CRYPTO-001 / CRYPTO-007 once wired through
the real pipeline. Pure packet construction, no live capture needed.
"""
from scapy.all import IP, TCP, wrpcap
import time

client = "10.0.12.41"
server = "198.51.100.25"
cport = 51422
sport = 25

pkts = []
seq_c, seq_s = 1000, 5000
t = time.time()

def add(src, dst, sport_, dport_, flags, seqn, ackn, payload=b""):
    global t
    t += 0.01
    pkt = IP(src=src, dst=dst) / TCP(sport=sport_, dport=dport_, flags=flags, seq=seqn, ack=ackn) / payload
    pkt.time = t
    pkts.append(pkt)

# 3-way handshake
add(client, server, cport, sport, "S", seq_c, 0); seq_c += 1
add(server, client, sport, cport, "SA", seq_s, seq_c); seq_s += 1
add(client, server, cport, sport, "A", seq_c, seq_s)

# Server banner
banner = b"220 mail.example.com ESMTP Postfix\r\n"
add(server, client, sport, cport, "PA", seq_s, seq_c, banner); seq_s += len(banner)
add(client, server, cport, sport, "A", seq_c, seq_s)

# EHLO
ehlo = b"EHLO client.example.com\r\n"
add(client, server, cport, sport, "PA", seq_c, seq_s, ehlo); seq_c += len(ehlo)
add(server, client, sport, cport, "A", seq_s, seq_c)

# EHLO response advertising STARTTLS
ehlo_resp = b"250-mail.example.com\r\n250-PIPELINING\r\n250 STARTTLS\r\n"
add(server, client, sport, cport, "PA", seq_s, seq_c, ehlo_resp); seq_s += len(ehlo_resp)
add(client, server, cport, sport, "A", seq_c, seq_s)

# Client proceeds with plaintext AUTH instead of STARTTLS (the vulnerable case)
auth = b"AUTH LOGIN\r\n"
add(client, server, cport, sport, "PA", seq_c, seq_s, auth); seq_c += len(auth)
add(server, client, sport, cport, "A", seq_s, seq_c)

auth_resp = b"334 VXNlcm5hbWU6\r\n"
add(server, client, sport, cport, "PA", seq_s, seq_c, auth_resp); seq_s += len(auth_resp)
add(client, server, cport, sport, "A", seq_c, seq_s)

# FIN
add(client, server, cport, sport, "FA", seq_c, seq_s); seq_c += 1
add(server, client, sport, cport, "FA", seq_s, seq_c); seq_s += 1
add(client, server, cport, sport, "A", seq_c, seq_s)

wrpcap("/home/claude/demo/data/sample_pcaps/smtp_starttls_unused.pcap", pkts)
print("wrote", len(pkts), "packets")
