#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>     // header IP
#include <net/ethernet.h>   // header Ethernet
#include <netinet/udp.h>    // header UDP
#include <netinet/tcp.h>    // header TCP
#include <sys/socket.h>     // conversion
#include <netinet/in.h>     // conversion
#include <arpa/inet.h>      // conversion
#include <unistd.h>         // getopt
#include "defs.h"
#include "utils.h"


int main(int argc, char * argv[]){
    
    char errbuf[PCAP_ERRBUF_SIZE], *name = "", *mydev = "";
    pcap_if_t *alldevs, *tmp;
    int c, iflag=0, oflag=0, verbosite=1; 
    FILE * fileflux;
    char * filepath;

    // analyse des options
    while((c = getopt(argc, argv, "i:o:f:v:")) != ERROR){
        switch(c){
            case 'i':
                // interface pour l'analyse live spécifiée
                mydev = optarg;
                iflag++;
                break;
            case 'o':
                // fichier d'entré pour pour analyse offline
                oflag++;
                filepath = optarg;
                break;
            case 'v':
                // niveau de verbosité (par défaut 1)
                verbosite = atoi(optarg);
                if((verbosite > COMPLET) || (verbosite < CONCIS)){
                    fprintf(stderr, "Erreur -v: vebosité %d inconnue\n", verbosite);
                    usage(argv);
                }
                break;
            case '?':
                usage(argv);
                break;
        }
    }

    if(!oflag){
        // si pas d'interface spécifiée (option -i) on en choisi une par défaut
        if(!iflag){
            printf("Pas d'interface spécifiée.\nRecherche d'une interface...\n");
            if(pcap_findalldevs(&alldevs ,errbuf) != 0){
                fprintf(stderr, "Erreur: \n%s", errbuf);
                exit(-1);
            }
            tmp = alldevs;
            int min;
            while(tmp != NULL){
                min = strlen(name) < strlen(tmp->name) ? strlen(name) : strlen(tmp->name);
                if(strncmp(name, tmp->name, min) != 0){
                    name = tmp->name;
                    printf("%s: %s\n", name, tmp->description);
                    tmp = alldevs->next;
                }
                else {
                    tmp = NULL;
                }
            }
            mydev = alldevs->name;
        }
        printf("Utilisation de l'interface %s\n", mydev);
    }
    else{
        // analyse hors ligne: fichier spécifié
        printf("Analyse hors ligne\n");
        printf("Ouverture du fichier %s...\n", filepath);
        if((fileflux = fopen(filepath, "r")) == NULL){
            fprintf(stderr, "Erreur: ouverture du fichier %s impossible\n", filepath);
            exit(EXIT_FAILURE);
        }
        fclose(fileflux);
        exit(EXIT_SUCCESS);
    }


    /**
     * CREER UNE SESSION DE SNIFFING
     * pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms,
	 * char *ebuf)
     */
    int BUFSIZE = 1500; // taille d'une trame
    int readTime = 0;
    pcap_t *handle;
    memset(errbuf, '0', PCAP_ERRBUF_SIZE);
    handle = pcap_open_live(mydev, BUFSIZE, 1, readTime, errbuf);
    if(handle == NULL){
        fprintf(stderr, "Erreur pcap_open_live: %s\n", errbuf);
        exit(-1);
    }
    
    /**
     * LIRE LE PROCHAIN PACKET
     * u_char* pcap_next(pcap_t *p, struct pcap_pkthdr *h) 
     */	
    const u_char * packet;
    struct pcap_pkthdr infos;
    struct ethhdr * ethernet;
    struct iphdr * ip;
    char ip_src[INET_ADDRSTRLEN], ip_dst[INET6_ADDRSTRLEN];
    char mac_src[MAC_SIZE], mac_dst[MAC_SIZE];
    u_int size_ip, size_transport;
    u_int8_t protocol;  // protocol au dessus de IP
    struct udphdr * udp;
    struct tcphdr * tcp;

    for(int i=0; i < 10; i++){
        if((packet = pcap_next(handle, &infos)) == NULL){
            fprintf(stderr, "Erreur pcap_next\n");
        }
        printf("lg=%d\n", infos.len);

        // entete Ethernet
        ethernet = (struct ethhdr *)(packet);
        
        // entete IP
        ip = (struct iphdr *)(packet + ETHERNET_SIZE);
        
        // taille entete ip
        size_ip = ip->ihl * 4;

        printf("-- ETHERNET --\n");
        getMac(ethernet->h_source, mac_src);
        getMac(ethernet->h_dest, mac_dst);
        printf("src: %s\n", mac_src);
        printf("dst: %s\n", mac_dst);

        printf("---- IPv4 ----\n");
        inet_ntop(AF_INET, &ip->saddr, ip_src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip->daddr, ip_dst, INET_ADDRSTRLEN);
        protocol = ip->protocol;
        printf("protocol: %d\n", protocol);
        printf("src: %s\n", ip_src);
        printf("dst: %s\n", ip_dst);
        printf("IHL = %u\n", ip->ihl);

        // protocol après IP
        switch(protocol){
            case IPPROTO_UDP:
                udp = (struct udphdr *)(packet + ETHERNET_SIZE + size_ip);
                size_transport = UDP_SIZE;
                printf("---- UDP ----\n");
                printf("src: %u\n", udp->source);
                printf("dst: %u\n", udp->dest);
                printf("%d\n", size_transport);
                break;
            case IPPROTO_TCP:
                printf("---- TCP ----\n");
                tcp = (struct tcphdr *)(packet + ETHERNET_SIZE + size_ip);
                size_transport = tcp->th_off * 4;
                printf("src: %u\n", tcp->source);
                printf("dst: %u\n", tcp->dest);
                break;
            default:
                printf("Protocol %d nous intéresse pas\n", protocol);
                break;
        }


        // APPLICATIF

        printf("--------------\n\n");

    }


    // fermer session
    pcap_freealldevs(alldevs);
    pcap_close(handle);

    return 0;
}