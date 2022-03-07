#include <net/ethernet.h>
#include <netinet/in.h>
//We used the code that were published for us in the model
//and this web https://www.winsocketdotnetworkprogramming.com/winsock2programming/winsock2advancedrawsocket11c.html
//ip header
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3,iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct  in_addr    iph_src;
    struct  in_addr    iph_dest;
};
//ether header
struct ethheader {
    u_char  ether_dhost[6];
    u_char  ether_shost[6];
    u_short ether_type;
};

//tcp header
struct tcpheader {
    unsigned short int tcph_srcport;
    unsigned short int tcph_destport;
    unsigned int       tcph_seqnum;
    unsigned int       tcph_acknum;
    unsigned char      tcph_reserved:4, tcph_offset:4;
    unsigned char      tcph_flags;
    unsigned short int tcph_win;
    unsigned short int tcph_chksum;
    unsigned short int tcph_urgptr;
};

