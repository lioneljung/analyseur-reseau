#include <stdlib.h>
#include <signal.h>
#include "defs.h"
#include "utils.h"
#include "ipv6.h"
#include "affichage.h"

volatile sig_atomic_t sigIntIn = 0; // réception d'un signal SIGINT

/**
 * Gestion signal
 */
void sigInt(__attribute__((unused))int sig)
{
	sigIntIn = 1;
}

/**
 * Analyse complète en live ou d'un fichier
 */
int analyse(const char *mydev, FILE *fileflux, int mode)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr infos;
    pcap_t *handle = NULL;
    int readTime = 0, compteur = 1;
    struct sigaction sint;

    // mise en place de la gestion du signal SIGINT
    sint.sa_handler = sigInt;
	sint.sa_flags = 0;
	sigemptyset(&sint.sa_mask);
	sigaddset(&sint.sa_mask, SIGQUIT);
	sigaction(SIGINT, &sint, NULL);

    if (fileflux == NULL)
    {
        // analyse en directe
        if ((handle = initSnifLive(mydev, readTime, errbuf)) == NULL)
        {
            fprintf(stderr, "Erreur pcap_open_live: %s\n", errbuf);
            return ERROR;
        }
        while (sigIntIn == 0)
        {
            // lire le prochain paquet
            if ((packet = pcap_next(handle, &infos)) == NULL)
                fprintf(stderr, "Impossible de lire un paquet\n%s\n", errbuf);
            analysePaquet(packet, infos, mode, compteur);
            compteur++;
        }
        pcap_close(handle);
    }
    else
    {
        // analyse à partir d'un fichier
        if ((handle = initSnifOffline(fileflux, errbuf)) == NULL)
        {
            fprintf(stderr, "Erreur pcap_fopen_offline: %s\n", errbuf);
            return ERROR;
        }
        while ((packet != NULL) && (sigIntIn == 0))
        {
            if ((packet = pcap_next(handle, &infos)) != NULL)
            {
                analysePaquet(packet, infos, mode, compteur);
                compteur++;
            }
        }
    }
    printf("\n%d paquets capturés.\n", compteur);
    return 0;
}

pcap_t *initSnifLive(const char *mydev, int readTime, char *errbuf)
{
    pcap_t *handle;
    handle = pcap_open_live(mydev, TRAMESIZE, 1, readTime, errbuf);
    return handle;
}

pcap_t *initSnifOffline(FILE *fichier, char *errbuf)
{
    pcap_t *handle;
    handle = pcap_fopen_offline(fichier, errbuf);
    return handle;
}


// analyse d'un paquet
void analysePaquet(const u_char *packet, struct pcap_pkthdr infos, int mode, int compteur)
{
    struct ethhdr *ethernet = NULL;
    struct iphdr *ip = NULL;
    struct ip6_hdr *ip6 = NULL;
    struct arphdr *arp = NULL;
    struct udphdr *udp = NULL;
    struct tcphdr *tcp = NULL;
    char *appdump = NULL;
    u_int size_ip, size_transport;
    u_int8_t protocol;
    int etherType;
    

    /**
     *  NIVEAU 2
     */
    ethernet = (struct ethhdr *)(packet);
    etherType = ntohs(ethernet->h_proto);

    /**
     *  NIVEAU 3
     */
    switch (etherType)
    {
        case ETH_P_ARP:
            arp = (struct arphdr *)(packet + ETHERNET_SIZE);
            break;
        
        case ETH_P_IP:
            ip = (struct iphdr *)(packet + ETHERNET_SIZE);
            size_ip = ip->ihl * 4;      // taille entete ip
            protocol = ip->protocol;    // protocole au dessus de IP
            break;

        case ETH_P_IPV6:
            ip6 = (struct ip6_hdr *)(packet + ETHERNET_SIZE);
            protocol = ip6->ip6_nxt;
            size_ip = analyseExtensionIp6(packet, ip6);
            break;
        
        case ETH_P_LOOPBACK:
            /**
             *  Ethernet Configuration Testing Protocol
             *  Permet de faire des tests sur le niveau 2 sur le loopback
             *  (similaire à echo au niveau 3)
             */
            break;

        default:
            fprintf(stderr, "(i) Ether type 0x%x not supported\n", etherType);
            return;
    }

    /**
     *  NIVEAU 4 (analyse du numéro de protocole dans IPv4)
     */
    if ((ip != NULL) || (ip6 != NULL))
    {
        switch (protocol)
        {
            case IPPROTO_UDP:
                udp = (struct udphdr *)(packet + ETHERNET_SIZE + size_ip);
                size_transport = UDP_SIZE;
                break;
            case IPPROTO_TCP:
                tcp = (struct tcphdr *)(packet + ETHERNET_SIZE + size_ip);
                size_transport = tcp->th_off * 4;
                break;
            case IPPROTO_ICMP:
                printf("Frame %d. %d bytes\tICMP\n", compteur, infos.len);
                return;
            case IPPROTO_IGMP:
                printf("Frame %d. %d bytes\tIGMP\n", compteur, infos.len);
                return;        
            case IPPROTO_ICMPV6:
                printf("Frame %d. %d bytes\tICMPv6\n", compteur, infos.len);
                return;
            default:
                printf("(i) IP protocol number %d not supported\n", protocol);
                return;
        }
    }

    /**
     * APPLICATIF
     */
    appdump = (char *)packet + ETHERNET_SIZE + size_ip + size_transport;

    /**
     *  AFFICHAGE SELON LE MODE CHOISI
     */
    printf("Frame %d. %d bytes\t", compteur, infos.len);
    switch (mode)
    {
        case CONCIS:
            if (etherType == ETH_P_ARP)
            {
                afficherARPConcis(arp);
                printf("\n");
                return; // plus rien après ARP
            }
            else if (etherType == ETH_P_IP)
                afficherIpConcis(ip);
            else if (etherType == ETH_P_IPV6)
                afficherIp6Concis(ip6);
            if ((tcp != NULL) || (udp != NULL))
                afficherTransportConcis(udp, tcp);
            // on vérifie qu'au dessus de TCP il y a de l'applicatif
            if (contientCoucheApplicative(tcp) == 0)        
                afficherApplicatifConcis(udp, tcp, appdump);
            printf("\n");
            break;

        case SYNTHE:
            printf("\n");
            afficherEthernetSynthe(ethernet);
            if (etherType == ETH_P_ARP)
            {
                afficherARPSynthe(arp);
                return; // plus rien après ARP
            }
            else if (etherType == ETH_P_IP)
                afficherIpSynthe(ip);
            else if (etherType == ETH_P_IPV6)
                afficherIp6Synthe(ip6);
            if ((tcp != NULL) || (udp != NULL))
                afficherTransportSynthe(udp, tcp);
            if (contientCoucheApplicative(tcp) == 0)
                afficherApplicatifSynthe(udp, tcp, appdump);
            printf("\n\n");            
            break;

        case COMPLET:
            printf("\n");
            afficherEthernetComplet(ethernet);
            if (etherType == ETH_P_ARP)
            {
                afficherARPComplet(arp);
                return; // plus rien après ARP
            }
            else if (etherType == ETH_P_IP)
                afficherIpComplet(ip);
            else if (etherType == ETH_P_IPV6)
                {}
            if ((tcp != NULL) || (udp != NULL))
                afficherTransportComplet(udp, tcp);
            if (contientCoucheApplicative(tcp) == 0)            
                afficherApplicatifComplet(udp, tcp, appdump);
            printf("\n\n");
            break;
        
        default:
            fprintf(stderr, "Erreur: mode %d inconnu.\n", mode);
            exit(EXIT_FAILURE);
    }

}