#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "utils.h"
#include "bootp.h"

void afficherBootpSynthe(char *appdump)
{
    struct bootp *hdr;
    if (appdump == NULL)
        return;
    hdr = (struct bootp*)appdump;

    printf("BOOTP: \t\t");

    if (hdr->bp_op == 1)
        printf("request");

    if (hdr->bp_op == 2)
        printf("reply");

}

void afficherBootpComplet(char *appdumpchar)
{
    struct bootp *hdr;
    char buf[INET_ADDRSTRLEN];
    int offset;
    if (appdumpchar == NULL)
        return;
    u_char *appdump = (u_char*) appdumpchar;
    hdr = (struct bootp*)appdump;

    printf("BOOTP\n");
    printf("\tMessage type: \t\t\t%d\n", hdr->bp_op);
    printf("\tHardware type:");
    if (hdr->bp_htype == 1)
        printf("\t\t\tEthernet");
    printf(" (%d)", hdr->bp_htype);
    printf("\n\tHardware Adresse Length: \t%d\n", hdr->bp_hlen);
    printf("\tHops: \t\t\t\t%d\n", hdr->bp_hops);
    printf("\tTransaction ID: \t\t0x%X\n", ntohl(hdr->bp_xid));
    printf("\tSecondes elapsed: \t\t%d\n", ntohs(hdr->bp_secs));
    printf("\tBootp Flags: \t0x%X\n", ntohs(hdr->bp_flags));
    printf("\tClient IP address: \t\t%s\n", inet_ntop(AF_INET, &hdr->bp_ciaddr, buf, INET_ADDRSTRLEN));
    printf("\tYour IP address: \t\t%s\n", inet_ntop(AF_INET, &hdr->bp_yiaddr, buf, INET_ADDRSTRLEN));
    printf("\tNext Server IP address: \t%s\n", inet_ntop(AF_INET, &hdr->bp_siaddr, buf, INET_ADDRSTRLEN));
    printf("\tRelay Agent IP address: \t%s\n", inet_ntop(AF_INET, &hdr->bp_giaddr, buf, INET_ADDRSTRLEN));
    printf("\tClient Hardware address: \t\t%s\n", hdr->bp_chaddr);
    printf("\tServer Host Name:");
    if (strlen((char*)hdr->bp_sname) == 0)
        printf(" not given\n");
    else
        printf(" %s\n", hdr->bp_sname);
    printf("\tBoot file:");
    if (strlen((char*)hdr->bp_file) == 0)
        printf(" not given\n");
    else
        printf(" %s\n", hdr->bp_file);
    // Pour DHCP: après CHADDR -> champs name et file (192 octets) sont à 0
    printf("\tMagic Cookie: ");
    if ((hdr->bp_vend[0] == 0x63) && (hdr->bp_vend[1] == 0x82) && (hdr->bp_vend[2] == 0x53) && (hdr->bp_vend[3] == 0x63))
    {
        printf("DHCP");
        // on enlève la partie vendor qu'on n'utilise pas
        appdump = appdump + sizeof(struct bootp) - 60; 
        // parser options DHCP
        while (appdump[0] != 255)
        {
            offset = 2; // octet code + longueur (pour avancer à la fin)
            printf("\n\tOption: (%d)\n", appdump[0]);
            // switch le code de l'option
            switch (appdump[0])
            {
                // padding
                case 0:
                    offset = 1;
                    break;
                
                // subnet mask
                case 1:
                    printf("\t | subnet mask: %d.%d.%d.%d", appdump[2], appdump[3], appdump[4], appdump[5]);
                    break;

                // Router option
                case 3:
                    printf("\t | Router option\n");
                    printf("\t | IP address: %d.%d.%d.%d", appdump[2], appdump[3], appdump[4], appdump[5]);
                    break;
                
                // DNS
                case 6:
                    printf("\t | Domain Name Server");
                    // on boucle pour le nombre de serveurs mentionné (addr taille 4)
                    for (int i = 2; i < appdump[1]; i = i+4)
                    {
                        printf("\n\t | IP address: %d.%d.%d.%d", appdump[i], appdump[i+1], appdump[i+2], appdump[i+3]);   
                    }
                    break;
                
                // IP requested
                case 50:
                    printf("\t | Requested IP Address\n");
                    printf("\t | IP address: %d.%d.%d.%d", appdump[2], appdump[3], appdump[4], appdump[5]);
                    break;

                // durée du bail
                case 51:
                    /**
                     *  L'affichage du nombre est incorrecte...
                     */
                    printf("\t | IP Address Lease Time\n");
                    unsigned long *time = (unsigned long*)appdump+2;
                    printf("\t | Time: %u secondes", ntohl(*time));
                    break;

                // option DHCP message type 
                case 53:
                    // type message
                    printf("\t | ");
                    switch(appdump[2])
                    {
                        case DHCPDISCOVER:
                            printf("DHCP Discover");
                            break;
                        case DHCPOFFER:
                            printf("DHCP Offer");
                            break;
                        case DHCPREQUEST:
                            printf("DHCP Request");
                            break;
                        case DHCPDECLINE:
                            printf("DHCP Decline");
                            break;
                        case DHCPACK:
                            printf("DHCP Ack");
                            break;
                        case DHCPNAK:
                            printf("DHCP NAck");
                            break;
                        case DHCPRELEASE:
                            printf("DHCP Release");
                            break;
                        case DHCPINFORM:
                            printf("DHCP Inform");
                            break;
                        default:
                            printf("error");
                            break;
                    }
                    break;
                
                // Informations voulus
                case 55:
                    printf("\t | Parameter Request List\n");
                    for (int i = 1; i <= appdump[1]; i++)
                        printf("\t | Parameter Request List Item: (%d)\n", appdump[1+i]);
                    break; 

                default:
                    printf("\t | not supported");
                    break;

            }
            printf("\n\t | length: %u", appdump[1]);
            // avancer selon la longueur + code et lg
            if (appdump[0] == 0)
                appdump += offset;
            else
                appdump += appdump[1] + offset;
        }
    }
}