#ifndef __HTTP_H
#define __HTTP_H

/**
 * \brief Affichage résumé de HTTP: on affiche la première ligne du message.
 */
void afficherHTTPsynthe(char * appdump);

/**
 * \brief Affichage complet de HTTP: on affiche tout le payload de HTTP.
 */
void afficherHTTPcomplet(char * appdump);


#endif