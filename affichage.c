#include <string.h>
#include "utils.h"
#include "defs.h"
#include "affichage.h"

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
    printf("ETHERNET\n");
    printf("\tsrc: %s \n\tdest: %s\n", mac_src, mac_dst);
    printf("\ttype: %d\n", ethernet->h_proto);    
}



/**
 *  ARP
 */

char * ARPtype(struct arphdr *arp)
{
    switch (arp->ar_op)
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
    return "unknown";
}

void afficherARPConcis(struct arphdr *arp)
{
    printf("ARP %s", ARPtype(arp));
}

void afficherARPSynthe(struct arphdr *arp)
{
    printf("ARP: \t\t");
    printf("type=%s - ", ARPtype(arp));
}

void afficherARPComplet(struct arphdr *arp)
{
    printf("ARP\n");
    printf("\ttype: %s\n", ARPtype(arp));
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
    printf("\tType of service: %d\n", ip->tos);
    printf("\tLength: %d\n", ip->tot_len);
    printf("\tid: %d\n", ip->id);
    printf("\tfrag. offset: %d\n", ip->frag_off);
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
        printf("\tlength: %d\n", udp->len);
        printf("\tchecksum: 0x%x\n", udp->check);
    }
    else if (tcp != NULL)
    {
        printf("TCP\n");
        printf("\tsrc: %hu\n", ntohs(tcp->source));
        printf("\tdst: %hu\n", ntohs(tcp->dest));
        printf("\tseq number: %u\n", tcp->seq);
        printf("\tack number: %u\n", tcp->ack_seq);
        printf("\toffset: %d\n", tcp->doff);
        printf("\tflags: C E U A P R S F\n");
        printf("\t       %d %d %d %d %d %d %d %d\n",
            tcp->res1, tcp->res2, tcp->urg, tcp->ack, 
            tcp->psh, tcp->rst, tcp->syn, tcp->fin);
        printf("\twindow: %d\n", tcp->window);
        printf("\tchecksum: 0x%x\n", tcp->check);
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




/**
 *  AFFICHAGE APPLICATIF
 */
// renvoie le numéro de port si type trouvé, -1 sinon
int afficherTypeApplicatif(uint16_t port, int afficher)
{
    switch (port)
    {
        case FTPDATA:
            if (afficher) 
                printf(" - FTP Data");
            return FTPDATA;
            break;

        case FTPCMD:
            if (afficher) 
                printf(" - FTP Command");
            return FTPCMD;
            break;

        case SSH:
            if (afficher)
                printf(" - SSH");
            return SSH;
            break;

        case TELNET:
            if (afficher)
                printf(" - TELNET");
            return TELNET;
            break;

        case SMTP:
            if (afficher)
                printf(" - SMTP");
            return SMTP;        
            break;
        
        case DNS:
            if (afficher)
                printf(" - DNS");
            return DNS;        
            break;
        
        case BOOTP_C:
            if (afficher)
                printf(" - BOOTP or DHCP client");
            return BOOTP_C;        
            break;

        case BOOTP_S:
            if (afficher)
                printf(" - BOOTP or DHCP server");
            return BOOTP_S;        
            break;
        
        case HTTP:
            if (afficher)
                printf(" - HTTP");
            return HTTP;        
            break;
        
        case POP3:
            if (afficher)
                printf(" - POP3");
            return POP3;        
            break;

        case NTP:
            if (afficher)
                printf(" - NTP");
            return NTP;
            break;

        case LDAP:
            if (afficher)
                printf(" - LDAP");
            return LDAP;
            break;
        
        case HTTPS:
            if (afficher)
                printf(" - HTTPS");
            return HTTPS;
            break;
        
        default:
            break;
    }
    return ERROR;
}

void afficherApplicatifConcis(struct udphdr *udp, struct tcphdr *tcp, char *appdump)
{
    uint16_t portsrc, portdst;
   
    // cas où la couche applicative est vide
    if (appdump == NULL) 
        return;
    
    if (udp != NULL)
    {
        portsrc = ntohs(udp->source);
        portdst = ntohs(udp->dest);
    }
    else if (tcp != NULL)
    {
        portsrc = ntohs(tcp->source);
        portdst = ntohs(tcp->dest);
    }

    // on regarde si le port d'un protocole applicatif connu apparait
    if (afficherTypeApplicatif(portsrc, 1) != ERROR) {}
    else if (afficherTypeApplicatif(portdst, 1) != ERROR) {}
}

void afficherApplicatifSynthe(struct udphdr *udp, struct tcphdr *tcp, char *appdump)
{
    uint16_t portsrc, portdst, port;
    // cas où la couche applicative est vide
    if (appdump == NULL) 
        return;

    // déterminer le protocole applicatif
    if (udp != NULL)
    {
        portsrc = ntohs(udp->source);
        portdst = ntohs(udp->dest);
    }
    else if (tcp != NULL)
    {
        portsrc = ntohs(tcp->source);
        portdst = ntohs(tcp->dest);
    }
    if (afficherTypeApplicatif(portsrc, 0) != ERROR)
        port = portsrc;
    else if (afficherTypeApplicatif(portdst, 0) != ERROR)
        port = portdst;

    // affichage selon port remarquable trouvé
    switch (port)
    {
        case DNS:
            afficherDNSsynthe(appdump);
            break;
        
        case HTTP:
            afficherHTTPsynthe(appdump);
            break;

        case HTTPS:
            printf("HTTPS - encrypted data\n");
            break;

        default:
            break;
    }
}

void afficherApplicatifComplet(struct udphdr *udp, struct tcphdr *tcp, char *appdump)
{
    uint16_t port, portsrc, portdst;
    // cas où la couche applicative est vide
    if (appdump == NULL) 
        return;
    
    // déterminer le protocole applicatif
    if (udp != NULL)
    {
        portsrc = ntohs(udp->source);
        portdst = ntohs(udp->dest);
    }
    else if (tcp != NULL)
    {
        portsrc = ntohs(tcp->source);
        portdst = ntohs(tcp->dest);
    }
    if (afficherTypeApplicatif(portsrc, 0) != ERROR)
        port = portsrc;
    else if (afficherTypeApplicatif(portdst, 0) != ERROR)
        port = portdst;

    // affichage selon port remarquable trouvé
    switch (port)
    {
        case DNS:
            afficherDNScomplet(appdump);
            break;

        case HTTP:
            afficherHTTPcomplet(appdump);
            break;

        case HTTPS:
            printf("HTTPS - encrypted data\n");
            break;

        default:
            break;
    }
}


/**
 *  AFFICHAGE DHCP
 */

/**
 * AFFICHAGE DNS
 */