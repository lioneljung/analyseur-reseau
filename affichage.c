#include <string.h>
#include <ctype.h>
#include "utils.h"
#include "defs.h"
#include "applicatif.h"

/**
 *  AFFICHAGE ETHERNET
 */
void afficherEthernetSynthe(struct ethhdr *ethernet)
{
    char mac_src[MAC_SIZE], mac_dst[MAC_SIZE];
    getMac(ethernet->h_source, mac_src);
    getMac(ethernet->h_dest, mac_dst);
    printf("ETHERNET: \t");
    printf("%s > %s\n", mac_src, mac_dst);
}

void afficherEthernetComplet(struct ethhdr *ethernet)
{
    char mac_src[MAC_SIZE], mac_dst[MAC_SIZE];
    getMac(ethernet->h_source, mac_src);
    getMac(ethernet->h_dest, mac_dst);
    printf("\nETHERNET\n");
    printf("\tsrc: %s \n\tdest: %s\n", mac_src, mac_dst);
    printf("\ttype: %d\n", ethernet->h_proto);    
}



/**
 *  ARP
 */

char * ARPtype(struct arphdr *arp)
{
    switch (ntohs(arp->ar_op))
    {
        case ARPOP_REQUEST:
            return "Request";
        case ARPOP_REPLY:
            return "Reply";
        case ARPOP_RREQUEST:
            return "RARP Request";
        case ARPOP_RREPLY:
            return "RARP Reply";
    }
    return "unknown ARP type";
}

char * ARPHardware(struct arphdr *arp)
{
    char *r = "";
    switch (ntohs(arp->ar_hrd))
    {
        case ARPHRD_ETHER:
            return "Ethernet 10/100 Mbps";
        
        default:
            snprintf(r, 3, "%d", ntohs(arp->ar_hrd));
            return r;
    }
}

void afficherARPConcis(struct arphdr *arp)
{
    printf("ARP %s\n", ARPtype(arp));
}

void afficherARPSynthe(struct arphdr *arp)
{
    printf("ARP: \t\t");
    printf("operation=%s - hardware type=%s\n", ARPtype(arp), ARPHardware(arp));
}

void afficherARPComplet(struct arphdr *arp, u_char *packet)
{
    int i;
    printf("ARP\n");
    printf("\tHardware type: %s (%d)\n", ARPHardware(arp), ntohs(arp->ar_hrd));
    printf("\tProtocol type:");
    if (ntohs(arp->ar_pro) == 0x0800)
        printf(" IP");
    printf(" (%d)\n", ntohs(arp->ar_pro));
    printf("\tHardware Address Length: %d\n", arp->ar_hln);
    printf("\tProtocol Address Length: %d\n", arp->ar_pln);
    printf("\tOperation: %s\n", ARPtype(arp));
    packet += ETHERNET_SIZE + sizeof(struct arphdr);
    printf("\tSender Hardware Address: ");
    for (i = 0; i < arp->ar_hln; i++)
    {
        printf("%X:", packet[0]);
        packet++;
    }
    printf("\n\tSender Protocol Address: ");
    for (i = 0; i < arp->ar_pln; i++)
    {
        printf("%d.", packet[0]);
        packet++;
    }
    printf("\n\tTarget Hardware Address: ");
    for (i = 0; i < arp->ar_hln; i++)
    {
        printf("%X:", packet[0]);
        packet++;
    }
    printf("\n\tTarget Protocol Address: ");
    for (i = 0; i < arp->ar_pln; i++)
    {
        printf("%d.", packet[0]);
        packet++;
    }
}



/**
 *  AFFICHAGE IP
 */
void afficherIpConcis(struct iphdr * ip)
{
    char ip_src[INET_ADDRSTRLEN], ip_dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, ip_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->daddr, ip_dst, INET_ADDRSTRLEN);
    printf("IPV4: ");
    printf("%s > %s - ", ip_src, ip_dst);
}

void afficherIpSynthe(struct iphdr * ip)
{
    char ip_src[INET_ADDRSTRLEN], ip_dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, ip_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->daddr, ip_dst, INET_ADDRSTRLEN);
    printf("IPV4: \t\t");
    printf("%s > %s - ", ip_src, ip_dst);
    printf("TTL=%d - ", ip->ttl);
    printf("protocol=%d", ip->protocol);
    printf("\n");
}

void afficherIpComplet(struct iphdr * ip)
{
    char ip_src[INET_ADDRSTRLEN], ip_dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, ip_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->daddr, ip_dst, INET_ADDRSTRLEN);
    printf("IPV4\n");
    printf("\tsrc: %s\n\tdest: %s\n", ip_src, ip_dst);
    printf("\tIHL: %d\n", ip->ihl);
    printf("\tType of service: %d\n", ntohs(ip->tos));
    printf("\tLength: %d\n", ntohs(ip->tot_len));
    printf("\tid: %d\n", ip->id);
    printf("\tfrag. offset: %d\n", ntohs(ip->frag_off));
    printf("\tTTL: %d\n", ip->ttl);
    printf("\tprotocol: %d\n", ip->protocol);
    printf("\tchecksum: 0x%x\n", ntohs(ip->check));
    if(ip->ihl > 5)
    {
        printf("\toptions:\n");
    }
}




/**
 *  AFFICHAGE COUCHE TRANSPORT
 */

char * tcptype(struct tcphdr *tcp)
{
    if (tcp->ack && tcp->syn)
        return "SYN+ACK";
    if (tcp->ack && tcp->psh)
        return "PUSH+ACK";
    if (tcp->ack)
        return "ACK";
    if (tcp->syn)
        return "SYN";
    if (tcp->fin)
        return "FIN";
    if (tcp->urg)
        return "URGENT";
    if (tcp->psh)
        return "PUSH";
    if (tcp->rst)
        return "RESET";
    if (tcp->res1)
        return "CWR";
    if (tcp->res2)
        return "ECE";
    return "unknown";
}

int contientCoucheApplicative(struct tcphdr *tcp)
{
    if (tcp == NULL)
        return 0;
    char * type = tcptype(tcp);
    if (strncmp(type, "ACK", 3) == 0)
        return ERROR;
    if (strncmp(type, "SYN+ACK", 7) == 0)
        return ERROR;
    if (strncmp(type, "SYN", 3) == 0)
        return ERROR;
    if (strncmp(type, "FIN", 3) == 0)
        return ERROR;
    return 0;
}

void afficherTransportConcis(struct udphdr *udp, struct tcphdr *tcp)
{
    if (udp != NULL)
    {
        printf("UDP: ");
        printf("src: %hu ", ntohs(udp->source));
        printf("dst: %hu", ntohs(udp->dest));
    }
    else if (tcp != NULL)
    {
        printf("TCP: ");
        printf("src: %hu ", ntohs(tcp->source));
        printf("dst: %hu", ntohs(tcp->dest));
    }
    else 
    {
        fprintf(stderr, "Couche transport inconnue: pas de TCP ni UDP\n");
        return;
    }
}

void afficherTransportSynthe(struct udphdr *udp, struct tcphdr *tcp)
{
    if (udp != NULL)
    {
        printf("UDP: \t\t");
        printf("src: %hu ", ntohs(udp->source));
        printf("dst: %hu\n", ntohs(udp->dest));
    }
    else if (tcp != NULL)
    {
        printf("TCP: \t\t");
        printf("src: %hu ", ntohs(tcp->source));
        printf("dst: %hu ", ntohs(tcp->dest));
        printf("type: %s", tcptype(tcp));
        printf("\n");
    }
    else 
    {
        fprintf(stderr, "Couche transport inconnue: pas de TCP ni UDP\n");
        return;
    }
}

void afficherTransportComplet(struct udphdr *udp, struct tcphdr *tcp)
{
    if (udp != NULL)
    {
        printf("UDP\n");
        printf("\tsrc: %hu\n", ntohs(udp->source));
        printf("\tdst: %hu\n", ntohs(udp->dest));
        printf("\tlength: %d\n", ntohs(udp->len));
        printf("\tchecksum: 0x%x\n", ntohs(udp->check));
    }
    else if (tcp != NULL)
    {
        printf("TCP\n");
        printf("\tsrc: %hu\n", ntohs(tcp->source));
        printf("\tdst: %hu\n", ntohs(tcp->dest));
        printf("\tseq number: %u\n", ntohs(tcp->seq));
        printf("\tack number: %u\n", ntohs(tcp->ack_seq));
        printf("\toffset: %d\n", ntohs(tcp->doff));
        printf("\tflags: C E U A P R S F\n");
        printf("\t       %d %d %d %d %d %d %d %d\n",
            tcp->res1, tcp->res2, tcp->urg, tcp->ack, 
            tcp->psh, tcp->rst, tcp->syn, tcp->fin);
        printf("\twindow: %d\n", ntohs(tcp->window));
        printf("\tchecksum: 0x%x\n", ntohs(tcp->check));
        printf("\turgent pointer: 0x%x\n", tcp->urg_ptr);
        if (tcp->doff > 5)
        {
            printf("\toptions:\n");
        }
    }
    else 
    {
        fprintf(stderr, "Couche transport inconnue: pas de TCP ni UDP\n");
        return;
    }    
}