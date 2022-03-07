#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#define SOURCE_IP "1.2.3.4"
#define DESTINATION_IP  "10.0.2.15"
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

void packet(struct iphdr* ip){//create raw socket
    struct sockaddr_in dest_in;
    int opt =1;

    int sock=socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (socket<0) { //check the creation of the socket
        perror("**ERROR** type_error: socket error\n");
        return; //there is an error
    }

    int set=setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    if (set<0) { //check the creation of the socket
        perror("**ERROR** type_error: setsockopt error\n");
        return; //there is an error
    }

    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = ip->daddr;

    int send=sendto(sock, ip, ntohs(ip->tot_len), 0, (struct sockaddr *)&dest_in, sizeof(dest_in));
    if (send<0) { //check the creation of the socket
        perror("**ERROR** type_error: sendto error\n");
        return; //there is an error
    }
    printf("The package was sent successfully\n");
    close(sock);
}




int main() {
    char buffer[IP_MAXPACKET];
    memset(buffer, 0, IP_MAXPACKET);

    struct icmp *icmp = (struct icmp *)(buffer + sizeof(struct iphdr));
    icmp->icmp_type = 0;//type 0 is Reply
    icmp->icmp_code =0;
    icmp ->icmp_cksum= calculate_checksum((unsigned short *)icmp, sizeof(struct icmphdr));

    struct iphdr *ip = (struct iphdr *)buffer;
    ip->version=4;
    ip->ihl=5;
    ip->tos=16;
    ip->id=htons(54321);
    ip->ttl=64;
    ip->saddr = inet_addr(SOURCE_IP);
    ip->daddr = inet_addr(DESTINATION_IP);
    ip->protocol = IPPROTO_ICMP;
    ip->tot_len= htons(100);

    packet(ip);

}


