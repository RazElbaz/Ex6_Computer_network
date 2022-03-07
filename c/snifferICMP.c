#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "headers.c"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 -> ip type
        struct ipheader * ip = (struct ipheader *)
                (packet + sizeof(struct ethheader));
        printf("SRC: %s\n", inet_ntoa(ip->iph_src));
        printf("DEST: %s\n", inet_ntoa(ip->iph_dest));
        if(ip->iph_protocol == 1){ //ICMP header is 1
            printf("ICMP packet\n\n");
        }

    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto icmp and host 10.0.2.15 and host 8.8.8.8";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}