#include <stdlib.h>
#include <signal.h>
#include "defs.h"
#include "utils.h"
#include "affichage.h"

volatile sig_atomic_t sigIntIn = 0; // réception d'un signal SIGINT

/**
 * \brief Fonction appeler lors d'un signal SIGINT
 */
void sigInt(__attribute__((unused))int sig){
	sigIntIn = 1;
}

int analyse(const char *mydev, FILE *fileflux, int mode)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr infos;
    pcap_t *handle = NULL;
    int readTime = 0;
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
        if ((handle = initSnif(mydev, readTime, errbuf)) == NULL)
        {
            fprintf(stderr, "Erreur pcap_open_live: %s\n", errbuf);
            return ERROR;
        }
        while (sigIntIn == 0)
        {
            // lire le prochain paquet
            if ((packet = pcap_next(handle, &infos)) == NULL)
                fprintf(stderr, "Impossible de lire un paquet\n%s\n", errbuf);
            analysePaquet(packet, infos, mode);
        }
        pcap_close(handle);
    }
    else
    {
        // analyse à partir d'un fichier
        while (sigIntIn == 0)
            ;
    }

    return 0;
}

pcap_t *initSnif(const char *mydev, int readTime, char *errbuf)
{
    pcap_t *handle;
    handle = pcap_open_live(mydev, TRAMESIZE, 1, readTime, errbuf);
    return handle;
}

void analysePaquet(const u_char *packet, struct pcap_pkthdr infos, int mode)
{
    struct ethhdr *ethernet;
    struct iphdr *ip;
    u_int size_ip, size_transport;
    u_int8_t protocol; // protocol au dessus de IP
    struct udphdr *udp = NULL;
    struct tcphdr *tcp = NULL;
    char *appdump;
    

    /**
     * ETHERNET
     */
    ethernet = (struct ethhdr *)(packet);

    /**
     * IP
     */
    ip = (struct iphdr *)(packet + ETHERNET_SIZE);
    size_ip = ip->ihl * 4;      // taille entete ip
    protocol = ip->protocol;    // protocole au dessus de IP
    if (ip->version != 4)
    {
        fprintf(stderr, "(i) IPv6 not supported\n");
        return;
    }

    /**
     * TCP & UDP
     */
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
            printf("ICMP");
            return;
        default:
            printf("Protocol %d ne nous intéresse pas\n", protocol);
            return;
    }

    /**
     * APPLICATIF
     */
    appdump = (char *)packet + ETHERNET_SIZE + size_ip + size_transport;

    /**
     *  AFFICHAGE SELON LE MODE CHOISI
     */
    printf("Taille: %d - ", infos.len);
    switch (mode)
    {
        case CONCIS:
            afficherIpConcis(ip);
            afficherTransportConcis(udp, tcp);
            afficherApplicatifConcis(udp, tcp, appdump);
            printf("\n");
            break;
        case SYNTHE:
            afficherEthernetSynthe(ethernet);
            printf("\n");            
            break;
        case COMPLET:
            printf("\n");
            break;
        default:
            fprintf(stderr, "Erreur: mode %d inconnu.\n", mode);
            exit(EXIT_FAILURE);
    }

}