#include "mainwindow.h"
#include <QApplication>

#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define PROMISCUOUS 1

struct ip *iph;
struct tcphdr *tcph;
struct ethernet *ethnet;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    //packet processing
    static int count = 1;
    struct ether_header *ep;
    unsigned short ether_type;
    int chcnt = 0;
    int length=pkthdr->len;

    ep=(struct ether_header * )packet;
    //ethernet header
    packet += sizeof(struct ether_header);
    ether_type = ntohs(ep->ether_type);

    if(ether_type == ETHERTYPE_IP){
        iph = (struct ip *)packet;
        printf("IP Packet\n");
        printf("Version         : %d\n", iph->ip_v);
        printf("Header Len      : %d\n", iph->ip_hl);
        printf("Ident           : %d\n", ntohs(iph->ip_id));
        printf("TTL             : %d\n", iph->ip_ttl);
        printf("shost Ethernet  : %02x:%02x:%02x:%02x:%02x:%02x\n", (ep->ether_shost[0]),(ep->ether_shost[1]),(ep->ether_shost[2]),(ep->ether_shost[3]),(ep->ether_shost[4]),(ep->ether_shost[5]));
        printf("dhost Ethernet  : %02x:%02x:%02x:%02x:%02x:%02x\n", (ep->ether_dhost[0]),(ep->ether_dhost[1]),(ep->ether_dhost[2]),(ep->ether_dhost[3]),(ep->ether_dhost[4]),(ep->ether_dhost[5]));
        printf("Source IP       : %s\n", inet_ntoa(iph->ip_src));
        printf("Destination IP  : %s\n", inet_ntoa(iph->ip_dst));

        if(iph->ip_p == IPPROTO_TCP){
            tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
            printf("Source Port      : %d\n", ntohs(tcph->th_sport));
            printf("Destination Port : %d\n", ntohs(tcph->th_dport));
        }
        while(length--){
            printf("%02x", *(packet++));
            if ((++chcnt% 16)== 0)
                printf("\n");
        }
    }else {
        printf("NON PACKET\n");
    }
    printf("\n\n");
}



int main(int argc, char *argv[])
{
    char *dev;
    char *net;
    char *mask;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;

    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    pcap_t *pcd;

    const u_char *packet;

    struct bpf_program fp;
    struct in_addr net_addr, mask_addr;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;

    dev=pcap_lookupdev(errbuf);
    if(dev ==NULL){
        printf("%s\n",errbuf);
        exit(1);
    }
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if(ret == -1){
        printf("%s\n", errbuf);
        exit(1);
    }
    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);
    if(net == NULL){
        perror("inet_ntoa");
        exit(1);
    }
    mask_addr.s_addr = maskp;
    mask = inet_ntoa(mask_addr);
    if(mask == NULL){
        perror("inet_ntoa");
        exit(1);
    }

    printf("DEV : %s\n", dev);
    printf("NET : %s\n",net);
    printf("MASK : %s\n", mask);
    printf("========================================================\n");

    pcd = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 100, errbuf);
    if (pcd==NULL){
        printf("%s\n", errbuf);
        exit(1);
    }
    if (pcap_compile(pcd, &fp, NULL, 0, netp) == -1){
        printf("compile error\n");
        exit(1);
    }
    if (pcap_setfilter(pcd, &fp) == -1){
        printf("setfilter error\n");
        exit(0);
    }
    pcap_loop(pcd, 0, callback, NULL);

    return 0;
}
