#!/usr/bin/python3
  
from scapy.all import *

def print_pkt(pkt):
    if pkt[1].src=='10.0.2.4':
        print("ttl = {}:".format(pkt[1].ttl))
        return
    if pkt[1].src=='20.205.243.166':
        print("arrived dst!")
    else:
        print("not arrived dst")


pkt=sniff(iface=['br-78bb728863e7','enp0s3'],filter='icmp',prn=print_pkt)
~         