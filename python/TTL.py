from telnetlib import IP
from scapy.all import *
from scapy.layers.inet import ICMP

a = IP()
a.dst = '157.240.221.174'
a.ttl
b = ICMP()
send(a/b)

for i in range(1,20):
	a.ttl = i
	send(a/b)