#!/usr/bin/env python3 
  
from scapy.all import *

a = IP(dst = '20.205.243.166')

b = ICMP()

p = a/b

for i in range(1,64):
    a.ttl=i
    send(a/b)
