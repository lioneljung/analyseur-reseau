#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "defs.h"
#include "utils.h"
#include "dns.h"
#include "applicatif.h"
#include "bootp.h"


void afficherASCIIsynthe(char *appdump, char *protocol)
{
    if (appdump == NULL)
        return;
    printf("%s: \t\t", protocol);
    while ((appdump[0] != '\n') && isprint(appdump[0]))
    {
        printf("%c", appdump[0]);
        appdump++;
    }
}

void afficherASCIIcomplet(char *appdump, char *protocol)
{
    int count = 0, sortieRapide = 0;
    if (appdump == NULL)
        return;
    if ((strncmp(protocol, "FTP", 3) == 0) || (strncmp(protocol, "TELNET", 6) == 0))
    {
        sortieRapide = 1;
    }
    printf("%s\n\t", protocol);
    while (appdump[0] != 0)
    {
        // 0x0D0A => saut à la ligne
        if ((appdump[0] == CR) && (appdump[1] == LF))
        {
            printf("\n");
            count = 0;
            if (sortieRapide)
            {
                return;
            }
        }
        // saut à la ligne si trop de caractère sans \n lu
        if (count == 120)
        {
            printf("\n\t");
            count = 0;
        }
        if (isprint(appdump[0]))
            printf("%c", appdump[0]);
        else
            printf(" ");
        if (appdump[0] == '\n')
            printf("\t");
        appdump++;
        count++;
    }
    printf("\n");
}

/**
 *  AFFICHAGE APPLICATIF
 */
// renvoie le numéro de port si type trouvé, -1 sinon
int afficherTypeApplicatif(uint16_t port, int afficher)
{
    switch (port)
    {
        case FTPDATA:
            if (afficher) 
                printf(" - FTP Data");
            return FTPDATA;

        case FTPCMD:
            if (afficher) 
                printf(" - FTP Command");
            return FTPCMD;

        case SSH:
            if (afficher)
                printf(" - SSH");
            return SSH;

        case TELNET:
            if (afficher)
                printf(" - TELNET");
            return TELNET;

        case SMTP:
            if (afficher)
                printf(" - SMTP");
            return SMTP;        
        
        case DNS:
            if (afficher)
                printf(" - DNS");
            return DNS;        
        
        case BOOTP_C:
            if (afficher)
                printf(" - BOOTP or DHCP");
            return BOOTP_C;        

        case BOOTP_S:
            if (afficher)
                printf(" - BOOTP or DHCP");
            return BOOTP_S;        
        
        case HTTP:
            if (afficher)
                printf(" - HTTP");
            return HTTP;        
        
        case POP3:
            if (afficher)
                printf(" - POP3");
            return POP3;        
            break;

        case NTP:
            if (afficher)
                printf(" - NTP");
            return NTP;

        case IMAP:
            if (afficher)
                printf(" - IMAP");
            return IMAP;

        case LDAP:
            if (afficher)
                printf(" - LDAP");
            return LDAP;
        
        case HTTPS:
            if (afficher)
                printf(" - HTTPS");
            return HTTPS;

        case DHCP6_C:
        if (afficher)
                printf(" - DHCP6");
            return DHCP6_C;
        
        case DHCP6_S:
            if (afficher)
                printf(" - DHCP6");
            return DHCP6_S;
        
        default:
            break;
    }
    return ERROR;
}

void afficherApplicatifConcis(struct udphdr *udp, struct tcphdr *tcp, char *appdump)
{
    uint16_t portsrc, portdst;
   
    // cas où la couche applicative est vide
    if (appdump == NULL) 
        return;
    
    if (udp != NULL)
    {
        portsrc = ntohs(udp->source);
        portdst = ntohs(udp->dest);
    }
    else if (tcp != NULL)
    {
        portsrc = ntohs(tcp->source);
        portdst = ntohs(tcp->dest);
    }

    // on regarde si le port d'un protocole applicatif connu apparait
    if (afficherTypeApplicatif(portsrc, 1) != ERROR) {}
    else if (afficherTypeApplicatif(portdst, 1) != ERROR) {}
}

void afficherApplicatifSynthe(struct udphdr *udp, struct tcphdr *tcp, char *appdump)
{
    uint16_t portsrc, portdst, port;
    int overTCP;
    
    // cas où la couche applicative est vide
    if (appdump == NULL) 
        return;

    // déterminer le protocole applicatif
    if (udp != NULL)
    {
        portsrc = ntohs(udp->source);
        portdst = ntohs(udp->dest);
    }
    else if (tcp != NULL)
    {
        portsrc = ntohs(tcp->source);
        portdst = ntohs(tcp->dest);
    }
    if (afficherTypeApplicatif(portsrc, 0) != ERROR)
        port = portsrc;
    else if (afficherTypeApplicatif(portdst, 0) != ERROR)
        port = portdst;

    // affichage selon port remarquable trouvé
    switch (port)
    {
        case FTPDATA:
        case FTPCMD:
            afficherASCIIsynthe(appdump, "FTP");
            break;

        case TELNET:
            afficherASCIIsynthe(appdump, "TELNET");
            break;
        
        case SMTP:
            afficherASCIIsynthe(appdump, "SMTP");
            break;

        case DNS:
            if (tcp == NULL) 
                overTCP = 0;
            else 
                overTCP = 1;
            afficherDNSsynthe(appdump, overTCP);
            break;

        case BOOTP_C:
        case BOOTP_S:
            afficherBootpSynthe(appdump);
            break;
        
        case HTTP:
            afficherASCIIsynthe(appdump, "HTTP");
            break;

        case POP3:
            afficherASCIIsynthe(appdump, "POP3");
            break;

        case IMAP:
            afficherASCIIsynthe(appdump, "IMAP");
            break;

        case HTTPS:
            printf("HTTPS - encrypted data\n");
            break;

        default:
            break;
    }
}

void afficherApplicatifComplet(struct udphdr *udp, struct tcphdr *tcp, char *appdump)
{
    uint16_t port, portsrc, portdst;
    int overTCP;

    // cas où la couche applicative est vide
    if (appdump == NULL) 
        return;
    
    // déterminer le protocole applicatif
    if (udp != NULL)
    {
        portsrc = ntohs(udp->source);
        portdst = ntohs(udp->dest);
    }
    else if (tcp != NULL)
    {
        portsrc = ntohs(tcp->source);
        portdst = ntohs(tcp->dest);
    }
    if (afficherTypeApplicatif(portsrc, 0) != ERROR)
        port = portsrc;
    else if (afficherTypeApplicatif(portdst, 0) != ERROR)
        port = portdst;

    // affichage selon port remarquable trouvé
    switch (port)
    {
        case FTPDATA:
            afficherASCIIcomplet(appdump, "FTP");
            break;
        
        case FTPCMD:
            afficherASCIIcomplet(appdump, "FTP");
            break;

        case TELNET:
            afficherASCIIcomplet(appdump, "TELNET");
            break;

        case DNS:
            if (tcp == NULL) 
                overTCP = 0;
            else 
                overTCP = 1;
            afficherDNScomplet(appdump, overTCP);
            break;

        case BOOTP_C:
        case BOOTP_S:
            afficherBootpComplet(appdump);
            break;

        case HTTP:
            afficherASCIIcomplet(appdump, "HTTP");
            break;
        
        case POP3:
            afficherASCIIcomplet(appdump, "POP3");
            break;

        case IMAP:
            afficherASCIIcomplet(appdump, "IMAP");
            break;
        
        case SMTP:
            afficherASCIIcomplet(appdump, "SMTP");
            break;

        case HTTPS:
            printf("HTTPS - encrypted data\n");
            break;

        default:
            break;
    }
}
