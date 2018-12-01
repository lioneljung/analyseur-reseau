#include "utils.h"
#include "defs.h"


/**
 *  AFFICHAGE ETHERNET
 */
void afficherEthernetSynthe(struct ethhdr *ethernet)
{
    char mac_src[MAC_SIZE], mac_dst[MAC_SIZE];
    getMac(ethernet->h_source, mac_src);
    getMac(ethernet->h_dest, mac_dst);
    printf("ETHERNET: ");
    printf("%s > %s - ", mac_src, mac_dst);
}

void afficherEthernetComplet(struct ethhdr *ethernet)
{
    char mac_src[MAC_SIZE], mac_dst[MAC_SIZE];
    getMac(ethernet->h_source, mac_src);
    printf("ETHERNET: ");
    printf("%s > %s", mac_src, mac_dst);    
    printf("\n");
}

/**
 *  AFFICHAGE IP
 */
void afficherIpConcis(struct iphdr * ip)
{
    char ip_src[INET_ADDRSTRLEN], ip_dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, ip_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->daddr, ip_dst, INET_ADDRSTRLEN);
    printf("IPv4: ");
    printf("%s > %s - ", ip_src, ip_dst);
}

/**
 *  AFFICHAGE COUCHE TRANSPORT
 */
void afficherTransportConcis(struct udphdr *udp, struct tcphdr *tcp)
{
    if (udp != NULL)
    {
        printf("UDP: ");
        printf("src: %hu ", ntohs(udp->source));
        printf("dst: %hu - ", ntohs(udp->dest));
    }
    else if (tcp != NULL)
    {
        printf("TCP: ");
        printf("src: %hu ", ntohs(tcp->source));
        printf("dst: %hu - ", ntohs(tcp->dest));
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
void afficherApplicatifConcis(struct udphdr *udp, struct tcphdr *tcp, char *appdump)
{
    uint16_t port;
    if (udp != NULL)
        port = udp->source;
    else if (tcp != NULL)
        port = tcp->source;
    printf("%c", appdump[0]);
    switch (port)
    {
        
    }
}

/**
 *  AFFICHAGE DHCP
 */

/**
 * AFFICHAGE DNS
 */