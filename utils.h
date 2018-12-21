#ifndef __UTILS_H
#define __UTILS_H

#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>   // header IP
#include <netinet/ip6.h>  // header IPv6
#include <net/ethernet.h> // header Ethernet
#include <linux/if_arp.h> // header ARP
#include <netinet/udp.h>  // header UDP
#include <netinet/tcp.h>  // header TCP
#include <sys/socket.h>   // conversion
#include <netinet/in.h>   // conversion
#include <arpa/inet.h>    // conversion

/**
 * \brief Affiche l'utilisation du programme
 */
void usage(char * argv[]);

/**
 * \brief Transforme une adresse MAC du header ethernet en chaine de caractères
 *  le résultat est copié dans dst
 */
void getMac(unsigned char * addr, char * dst);

/**
 * \brief L'analyse du trafic réseau se passe ici.
 * \return Renvoie -1 en cas d'erreur
 */
int analyse(const char *mydev, FILE *fileflux, int mode, char *filtre);

/**
 * \brief Initialisation d'une session de sniffing en directe.
 */
pcap_t *initSnifLive(const char *mydev, int readTime, char *errbuf);

/**
 * \brief Initialisation d'une session de lecture de paquets dans un fichier.
 */
pcap_t *initSnifOffline(FILE *fichier, char *errbuf);

/**
 * \brief Applique un filtre sur handle si "filtre" n'est pas NULL
 */
void appliquerFiltre(pcap_t *handle, char *filtre);

/**
 * \brief Analyse d'un paquet. Affichage selon le mode choisi.
 */
void analysePaquet(const u_char *packet, struct pcap_pkthdr infos, int mode, int compteur);

#endif