#ifndef __IPV6_H
#define __IPV6_H

/**
 * \brief Cette fonction permet de déterminer la taille d'ipv6 avec les extensions
 * et options minimales nécessaires d'après la RFC 8200. Renvoie -1 dans le cas
 * que le numéro de protocol indique un header qu'il faudra gérer.
 */
u_int analyseExtensionIp6(const u_char *packet, struct ip6_hdr *ip6);

/**
 * \brief Affichage concis du header ipv6
 */
void afficherIp6Concis(struct ip6_hdr * ip);

#endif