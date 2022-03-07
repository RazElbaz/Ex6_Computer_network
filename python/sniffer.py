#!/usr/bin/env python3
from scapy.all import *


def print_pkt(pkt):
    pkt.show()

#TasK 1.1B filters:

pkt = sniff(iface ='enp0s3', filter='icmp', prn=print_pkt)

#pkt = sniff(iface ='enp0s3',filter='tcp and dst port 23 ans src host 10.0.2.15', prn=print_pkt)

#pkt = sniff(iface ='enp0s3' ,filter='net 8.0.0.0/24', prn=print_pkt)