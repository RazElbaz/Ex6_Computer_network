#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "headers.c"


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethheader* eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 -> ip type
        struct ipheader * ip = (struct ipheader *)
                (packet + sizeof(struct ethheader));

        printf("SRC: %s\n", inet_ntoa(ip->iph_src));
        printf("DEST: %s\n", inet_ntoa(ip->iph_dest));

        if(ip->iph_protocol==6) {
        char *data = (u_char *)packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcpheader);
        int sizeData = ntohs(ip->iph_len) - (sizeof(struct ipheader) + sizeof(struct tcpheader));
        if (sizeData>0) {
            data=data+12;
            printf("%c\n", *data);
        }

    }
}}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "port 23";
    bpf_u_int32 net;

    // step 1: open live pcap session on NIC with interface name
    handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);

    // step 2: compile filter_exp into BPF pseudo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // step 3: capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // close the handle

    return 0;
}