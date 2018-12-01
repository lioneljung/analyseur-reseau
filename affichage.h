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
 * \brief Affichage conçis de l'entête IP.
 */
void afficherIpConcis(struct iphdr * ip);

/**
 * \brief Affichage conçis de la couche transport.
 */
void afficherTransportConcis(struct udphdr *udp, struct tcphdr *tcp);

/**
 * \brief Affichage du protocole applicatif de manière conçise
 */
void afficherApplicatifConcis(struct udphdr *udp, struct tcphdr *tcp, char *appdump);

#endif