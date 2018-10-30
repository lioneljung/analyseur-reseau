#include <stdio.h>
#include <stdlib.h>
#include "defs.h"


void usage(char * argv[]){
    printf("Ce programme permet de voir le trafic réseau.\n");
    printf("usage: %s [-i <interface>] [-o <fichier>] [-v <1..3>]\n", argv[0]);
    printf("option:\n");
    printf("\t-i: indiquer l'interface réseau dont l'on veut voir le trafic\n");
    printf("\t-o: spécifier un fichier pour analyser le traffic hors ligne\n");
    printf("\t-v: indiquer la verbosité du programme:\n");
    printf("\t\t- 1 = très concis\n");
    printf("\t\t- 2 = synthétique\n");
    printf("\t\t- 3 = complet\n");
    exit(EXIT_FAILURE);
}


void getMac(unsigned char * addr, char * dst){
    snprintf(dst, MAC_SIZE, "%X:%X:%X:%X:%X:%X",
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}