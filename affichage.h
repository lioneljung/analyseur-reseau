#ifndef __AFFICHAGE_H
#define __AFFICHAGE_H

/**
 * \brief affichage synthétique de l'entête Ethernet.
 */
void afficherEthernetSynthe(struct ethhdr *ethernet);

/**
 * \brief Affichage complet de l'entête Ethernet.
 */
void afficherEthernetComplet(struct ethhdr *ethernet);

/**
 * \brief Affichage conçis pour ARP
 */
void afficherARPConcis(struct arphdr *arp);

/**
 * \brief Affichage synthétique pour ARP
 */
void afficherARPSynthe(struct arphdr *arp);

/**
 * \brief Affichage complet pour ARP
 */
void afficherARPComplet(struct arphdr *arp);

/**
 * \brief Affichage conçis de l'entête IP.
 */
void afficherIpConcis(struct iphdr *ip);

/**
 * \brief Affichage synthétique de l'entête IP.
 */
void afficherIpSynthe(struct iphdr *ip);

/**
 * \brief Affichage complet de l'entête IP.
 */
void afficherIpComplet(struct iphdr *ip);

/**
 * \brief Renvoie le type de TCP (chaine de caractère)
 */
char * tcptype(struct tcphdr *tcp);

/**
 * \brief Indique si le datagramme TCP transporte de l'applicatif;
 * renvoie 0 si c'est le cas, -1 sinon.
 */
int contientCoucheApplicative(struct tcphdr *tcp);

/**
 * \brief Affichage conçis de la couche transport.
 */
void afficherTransportConcis(struct udphdr *udp, struct tcphdr *tcp);

/**
 * \brief Affichage synthetique de la couche transport.
 */
void afficherTransportSynthe(struct udphdr *udp, struct tcphdr *tcp);

/**
 * \brief Affichage complet de la couche transport.
 */
void afficherTransportComplet(struct udphdr *udp, struct tcphdr *tcp);

/**
 * \brief Affichage du protocole applicatif de manière conçise
 */
void afficherApplicatifConcis(struct udphdr *udp, struct tcphdr *tcp, char *appdump);

/**
 * \brief Affichage du protocole applicatif de manière synthétique
 */
void afficherApplicatifSynthe(struct udphdr *udp, struct tcphdr *tcp, char *appdump);

/**
 * \brief Affichage du protocole applicatif de manière complète
 */
void afficherApplicatifComplet(struct udphdr *udp, struct tcphdr *tcp, char *appdump);

/**
 *  Protocoles applicatifs définies dans d'autres fichiers
 */
#include "dns.h"
#include "http.h"

#endif