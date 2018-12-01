#ifndef __DEFS_H
#define __DEFS_H

#define ETHERNET_SIZE 14    // taille header ethernet
#define MAC_SIZE      18    // nb caractères addr MAC
#define UDP_SIZE      8     // taille header UDP
#define ERROR        -1     // renvoie d'erreur
#define TRAMESIZE     1500  // taille max d'une trame

// niveau de verbosité pour option -v
enum{NONE, CONCIS, SYNTHE, COMPLET};

/**
 *  PORT APPLICATIF CONNU
 */
#define FTP     21
#define SMTP    25
#define DNS     53
#define DHCP    67
#define HTTP    80
#define POP3    110
#define HTTPS   443

#endif