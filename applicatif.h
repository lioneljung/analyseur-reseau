#ifndef __APPLICATIF_H
#define __APPLICATIF_H

/**
 * \brief Affichage résumé de HTTP: on affiche la première ligne du message.
 */
void afficherASCIIsynthe(char * appdump, char *protocol);

/**
 * \brief Affichage complet de HTTP: on affiche tout le payload de HTTP.
 */
void afficherASCIIcomplet(char *appdump, char *protocol);

/**
 * \brief Retourne le protocol applicatif selon le port
 * Permet aussi d'afficher le nom du protocol si afficher = 1
 */
int afficherTypeApplicatif(uint16_t port, int afficher);

/**
 * \brief Affiche le contenu applicatif de manière conçise (le nom du protocole)
 */
void afficherApplicatifConcis(struct udphdr *udp, struct tcphdr *tcp, char *appdump);

/**
 * \brief Affiche le contenu applicatif de manière syntétique (1 ligne)
 */
void afficherApplicatifSynthe(struct udphdr *udp, struct tcphdr *tcp, char *appdump);

/**
 * \brief Affiche le contenu applicatif de manière complète (tout le contenu)
 */
void afficherApplicatifComplet(struct udphdr *udp, struct tcphdr *tcp, char *appdump);


#endif