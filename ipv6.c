#include "utils.h"
#include "defs.h"
#include <stdlib.h>
#include <stdio.h>

int estTerminal(u_int8_t protocol)
{
    // on ne gère que les protocoles requis par la RFC 8200
    switch (protocol)
    {
        case IPPROTO_IP:        // hop by hop option
        case IPPROTO_FRAGMENT:  // Fragment header
        case MY_IPPROTO_DEST:   // destination options for ipv6
        case IPPROTO_ROUTING:   // Routing header for ipv6
        case IPPROTO_AH:        // Authentification Header
        case IPPROTO_ESP:       // Encapsulating security payload
            return ERROR;
    }
    return 0;
}

// renvoie la taille totale d'IPv6 dans le paquet
u_int analyseExtensionIp6(const u_char *packet, struct ip6_hdr *ip6)
{
    u_int8_t protocol = ip6->ip6_nxt;
    u_int size = IP6_SIZE;
    struct ip6_ext *extension;

    while (estTerminal(protocol) == ERROR)
    {
        extension = (struct ip6_ext*)(packet+ETHERNET_SIZE+size);
        size += extension->ip6e_len * 8;
        protocol = extension->ip6e_nxt;
    }
    return size;
}

void afficherIp6Concis(struct ip6_hdr * ip)
{
    char ip_src[INET6_ADDRSTRLEN], ip_dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip->ip6_src, ip_src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip->ip6_dst, ip_dst, INET6_ADDRSTRLEN);
    printf("IPV6: ");
    printf("%s > %s - ", ip_src, ip_dst);
}