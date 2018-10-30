#ifndef __UTILS_H
#define __UTILS_H



/**
 * \brief Affiche l'utilisation du programme
 */
void usage(char * argv[]);


/**
 * \brief Transforme une adresse MAC du header ethernet en chaine de caractères
 *  le résultat est copié dans dst
 */
void getMac(unsigned char * addr, char * dst);


#endif