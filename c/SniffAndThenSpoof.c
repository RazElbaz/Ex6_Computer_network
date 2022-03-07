#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include "headers.c"
#define IP_MAXPACKET 65535

//We used the code that were published for us in the model
unsigned short calculate_checksum(unsigned short *paddress, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *((unsigned char *) &answer) = *((unsigned char *) w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}

int spoofReply (const u_char *packet)
{
    char buf[IP_MAXPACKET];//create an array for thr packets
    bzero(buf, sizeof(buf)); //The  bzero()  function  erases  the  data  in the n bytes of the memory starting at the location pointed to by s
    memcpy(buf, (packet + sizeof(struct ethheader)), sizeof(buf)); // The  memcpy()  function  copies  n bytes from memory area src to memoryarea dest.

    char *buffer = buf;
    struct ipheader *tempIPH= (struct ipheader *)(buffer);

    struct icmp * icmp = (struct icmp*)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
    icmp->icmp_type = 0;//type 0 is Reply
    icmp->icmp_cksum =calculate_checksum((unsigned short *)icmp, sizeof(struct icmphdr));

    //create with a temporary struct the spoof replay
    struct in_addr current = tempIPH->iph_dest;
    tempIPH->iph_dest=tempIPH->iph_src;
    tempIPH->iph_src=current;


    struct sockaddr_in  dest_in;
    dest_in.sin_family = AF_INET;
    inet_pton(AF_INET, inet_ntoa(tempIPH->iph_dest), &dest_in.sin_addr.s_addr); //This  function converts the character string src into a network address structure in the af address family, then  copies  the  network  address structure  to dest_in.
    dest_in.sin_port = htons(0);  //The htonl() function converts the unsigned integer hostlong  from  host byte order to network byte order.

    int opt =1;
    int sock=socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock<0) { //check the creation of the socket
        perror("**ERROR** type_error: socket error\n");
        return -1; //there is an error
    }
    int set=setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    if (set<0) { //check the setsockopt
        perror("**ERROR** type_error: setsockopt error\n");
        return -1; //there is an error
    }
    int send=sendto(sock, buf, sizeof(buf), 0, (struct sockaddr *)&dest_in, sizeof(dest_in));
    if (send<0) { //check the sending of the socket
        perror("**ERROR** type_error: sendto error\n");
        return -1; //there is an error
    }

    close(sock); //close the socket

}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 -> ip type
        struct ipheader * ip = (struct ipheader *)
                (packet + sizeof(struct ethheader));
        printf("SRC: %s\n", inet_ntoa(ip->iph_src));
        printf("DEST: %s\n", inet_ntoa(ip->iph_dest));
        if(ip->iph_protocol == 1){ //ICMP header is 1
            printf("ICMP packet\n\n");
            spoofReply(packet);
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
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

