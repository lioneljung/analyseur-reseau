#ifndef __DEFS_H
#define __DEFS_H

/**
 *  Général
 */
#define ERROR           -1      // renvoie d'erreur

/**
 *  niveau de verbosité pour option -v (NONE permet de neutralisé le 0)
 */
enum{NONE, CONCIS, SYNTHE, COMPLET};

/**
 *  Extensions & options IPv6 non trouvés
 */
#define MY_IPPROTO_DEST    60

/**
 * Tailles
 */
#define ETHERNET_SIZE   14      // taille header ethernet
#define MAC_SIZE        18      // nb caractères addr MAC (':' compris)
#define UDP_SIZE        8       // taille header UDP
#define IP6_SIZE        40      // taille header IPv6
#define TRAMESIZE       1500    // taille max d'une trame ethernet

/**
 *  ASCII
 */
#define CR  13
#define LF  10

/**
 *  PORTS APPLICATIFS CONNUS
 *  On en "gère" quelques uns de plus que vu en cours pour un affichage plus
 *  complet dans le cas de l'affichage concis sur le réseau local à la maison.
 */ 
#define FTPDATA     20
#define FTPCMD      21
#define SSH         22
#define TELNET      23
#define SMTP        25
#define DNS         53
#define BOOTP_S     67  // server
#define BOOTP_C     68  // client
#define HTTP        80
#define POP3        110
#define NTP         123
#define LDAP        389
#define HTTPS       443

#endif