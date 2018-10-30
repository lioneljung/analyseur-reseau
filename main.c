#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ethernet.h>

#define ETHERNET_SIZE 14

int main(){
    
    char errbuf[PCAP_ERRBUF_SIZE], *name = "", *mydev = "";
    pcap_if_t *alldevs, *tmp;
    
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

    // nom interface "any" = sniffer toutes les interfaces
    mydev = alldevs->name;
    printf("Using first interface called %s\n", mydev);

    /**
     * CREER UNE SESSION DE SNIFFING
     * pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms,
	 * char *ebuf)
     */
    int BUFSIZE = 1500;     // taille d'une trame
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
    struct sniff_ethernet * ethernet;
    for(int i=0; i < 10; i++){
        if((packet = pcap_next(handle, &infos)) == NULL){
            fprintf(stderr, "Erreur pcap_next\n");
        }
        printf("lg=%d\n", infos.len);
        ethernet = (struct sniff_ethernet *)packet;
    }

    /**
     * Parser Ethernet avec ethernet.h
     */

    // fermer session
    pcap_freealldevs(alldevs);
    pcap_close(handle);

    return 0;
}