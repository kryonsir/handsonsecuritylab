#!/usr/bin/python
from scapy.all import *

def send_packet(pkt):

    if ICMP in pkt and pkt[ICMP].type == 8:
        print("request: src {} dst {}".format(pkt[1].src,pkt[1].dst))
        ip = IP(src=pkt[1].dst,dst=pkt[1].src)
        if pkt[1].dst=='8.8.8.8':
            ip.src='8.8.8.9'
        icmp = ICMP(type=0,id=pkt[2].id,seq=pkt[2].seq)

        data=pkt[3].load
        newpkt = ip/icmp/data
        print("response: src {} dst {}".format(pkt[1].dst,pkt[1].src))
        send(newpkt,verbose=0)

interfaces = ['br-78bb728863e7','enp0s3','lo','docker0','vetha6693f7','vetha6d110c']
pkt = sniff(iface=interfaces, filter='icmp', prn=send_packet)
