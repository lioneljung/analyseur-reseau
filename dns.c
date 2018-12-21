#include <stdio.h>
#include "utils.h"
#include "defs.h"
#include "dns.h"

void afficherDNSsynthe(char *appdump, int overTCP)
{
    struct dnshdr *hdr;
    if (appdump == NULL)
        return;

    // si on a du DNS-over-TCP, on ignore les 2 premiers octets
    if (overTCP)
        appdump += 2;

    hdr = (struct dnshdr *)appdump;
    printf("DNS: \t\t");

    // affichage type d'opération
    switch (hdr->opcode)
    {
    case DNS_OPCODE_QUERY:
        printf("Query - ");
        break;

    case DNS_OPCODE_IQUERY:
        printf("Inverse query - ");
        break;

    case DNS_OPCODE_STATUS:
        printf("Status request - ");
        break;

    case DNS_OPCODE_NOTIFY:
        printf("Notify - ");
        break;

    case DNS_OPCODE_UPDATE:
        printf("Update - ");
        break;
    }

    printf("\n");
}

void afficherDNScomplet(char *appdump, int overTCP)
{
    struct dnshdr *hdr;
    short *size, *type;
    char lg;
    char *bakptr;
    if (appdump == NULL)
        return;

    printf("DNS\n");

    // Si over TCP, les 2 premiers octets représentent la taille
    if (overTCP)
    {
        size = (short *)appdump;
        appdump += 2;
        printf("\tLength: %d\n", ntohs(*size));
    }

    hdr = (struct dnshdr *)appdump;
    bakptr = appdump;

    // identifiant
    printf("\tTransaction ID: 0x%x", ntohs(hdr->id));
    printf("\n");

    // QR (query or reply)
    printf("\tQR: %d - ", hdr->qr);
    if (hdr->qr == 0)
        printf("query\n");
    else
        printf("response\n");

    // affichage type d'opération
    printf("\tOpcode: %d - ", hdr->opcode);
    switch (hdr->opcode)
    {
    case DNS_OPCODE_QUERY:
        printf("Standard query");
        break;

    case DNS_OPCODE_IQUERY:
        printf("Inverse query");
        break;

    case DNS_OPCODE_STATUS:
        printf("Status request");
        break;

    case DNS_OPCODE_NOTIFY:
        printf("Notify");
        break;

    case DNS_OPCODE_UPDATE:
        printf("Update");
        break;
    }
    printf("\n");

    // AA (Authoritative Answer)
    printf("\tAA: %d", ntohs(hdr->aa));
    printf("\n");

    // TC (TrunCation)
    printf("\tTruncated: %d", hdr->tc);
    printf("\n");

    // RD (Recursion Desired)
    printf("\tRecursion desired: %d", hdr->rd);
    printf("\n");

    // RA (Recursion Available)
    printf("\tRecursion available: %d", hdr->ra);
    printf("\n");

    // Z (Reserved for future use)
    printf("\tZ (future use): %d", ntohs(hdr->zero));
    printf("\n");

    // AA (Answer Authentification)
    printf("\tAnswer Authentification: %d", hdr->aa);
    printf("\n");

    // RCODE (Response code)
    printf("\tRCODE: %d", ntohs(hdr->rcode));
    if (hdr->qr == 1)
    {
        if (ntohs(hdr->rcode) == 0)
            printf(" - no error condition");
        else
            printf(" - error");
    }
    printf("\n");

    // QDCOUNT
    printf("\tQuestions: %d", ntohs(hdr->qcount));
    printf("\n");

    // ANCOUNT
    printf("\tAnswer RRs: %d", ntohs(hdr->ancount));
    printf("\n");

    // NSCOUNT
    printf("\tAuthority RRs: %d", ntohs(hdr->nscount));
    printf("\n");

    // ADCOUNT
    printf("\tAdditional RRs: %d", ntohs(hdr->adcount));
    printf("\n");

    // on saute le header dans APPDUMP
    appdump += sizeof(struct dnshdr); //DNS_HDR_SIZE;

    // Queries
    if (ntohs(hdr->qcount) > 0)
    {
        printf("\tQueries:");
        for (int i = 0; i < ntohs(hdr->qcount); i++)
        {
            printf("\n\t\t > ");
            // parser tous les labels du nom de domaine
            while (appdump[0] != 0)
            {
                lg = appdump[0];
                appdump++;
                // affichage du label octet par octet
                for (int j = 0; j < lg; j++)
                {
                    printf("%c", appdump[0]);
                    appdump++;
                }
                printf(".");
            }

            // ignorer le caractère NULL qui marque la fin du DN
            appdump++;

            // affichage des informations sur le DN
            printf("\n");
            type = (short *)appdump;
            printf("\t\t\t  query type: %d\n", ntohs(*type));
            appdump += 2;
            type = (short *)appdump;
            printf("\t\t\t  query class: %d\n", ntohs(*type));
            appdump += 2;
        }
    }

    // Answers
    printf("\tAnswers:");
    printf("\n\t\t > ");


/**      
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    for (int i = 0; i < hdr->adcount + hdr->ancount; i++)
    {
        // checker si pointeur vers DN = les deux premiers bits à 1
        if ((u_char)appdump[0] >= 192)
        {
            printf ("/!\\pointer");
            appdump += 2;
        }
        else
        {
            while (appdump[0] != 0)
            {
                lg = appdump[0];
                appdump++;
                // affichage du label octet par octet
                for (int j = 0; j < lg; j++)
                {
                    printf("%c", appdump[0]);
                    appdump++;
                }
                printf(".");
            }
            if(bakptr) {}
        }
        
        // ignorer le caractère NULL qui marque la fin du DN
        appdump++;

        // Parser type
        type = (short *)appdump;
        printf("\n\t\t > Type: %d", ntohs(*type));
        appdump += 2;
        
        return; // On sort ici car le reste n'est pas encore géré

        // parser class 
        appdump += 2;

        // parser TTL
        appdump += 8;

        // parser RDLength
        appdump += 4;

        // parser RDATA
        appdump += 4; // peut être variable...

    }

    printf("\n");
}