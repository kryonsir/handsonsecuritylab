from scapy.all import *
def print_pkt(pkt):
	pkt.show()
print(sniff(iface="br-87102073d3bd",filter="tcp port 23",prn=print_pkt))
