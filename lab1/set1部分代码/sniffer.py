#!/usr/bin/env python3
from scapy.all import *

print("start")

def print_pkt(pkt):
    print_pkt.num_packets+=1
    print("\n==============packet: {}===============\n".format(print_pkt.num_packets))
    pkt.show()

print_pkt.num_packets=0

# pkt = sniff(iface=['br-78bb728863e7','enp0s3'],filter='tcp && src host 10.9.0.1 && dst port 23',prn=print_pkt)

# pkt = sniff(iface=['br-78bb728863e7','enp0s3','lo'],filter='dst net 128.230.0.0/16',prn=print_pkt)


pkt=sniff(iface=['br-78bb728863e7','enp0s3'],filter='icmp',prn=print_pkt)
