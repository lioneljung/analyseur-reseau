#include <stdlib.h>
#include <string.h>
#include <unistd.h> // getopt
#include "defs.h"
#include "utils.h"

int main(int argc, char *argv[])
{
    char *name = "";
    char *mydev = "";
    char *filepath;
    char errbuf[PCAP_ERRBUF_SIZE];    
    pcap_if_t *alldevs;
    pcap_if_t *tmp;
    int c, iflag = 0, oflag = 0, verbosite = CONCIS;
    FILE *fileflux = NULL;
    memset(errbuf, '0', PCAP_ERRBUF_SIZE);

    // analyse des options
    while ((c = getopt(argc, argv, "i:o:f:v:")) != ERROR)
    {
        switch (c)
        {
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
            if ((verbosite > COMPLET) || (verbosite < CONCIS))
            {
                fprintf(stderr, "Erreur -v: vebosité %d inconnue\n", verbosite);
                usage(argv);
            }
            break;
        case '?':
            usage(argv);
            break;
        }
    }

    // gestion des options
    if (!oflag)
    {
        // si pas d'interface spécifiée (option -i) on en choisi une par défaut
        if (!iflag)
        {
            printf("Pas d'interface spécifiée.\nRecherche d'une interface...\n");
            if (pcap_findalldevs(&alldevs, errbuf) != 0)
            {
                fprintf(stderr, "Erreur: findalldevs\n%s", errbuf);
                exit(-1);
            }
            tmp = alldevs;
            int min;
            while (tmp != NULL)
            {
                min = strlen(name) < strlen(tmp->name) ? strlen(name) : strlen(tmp->name);
                if (strncmp(name, tmp->name, min) != 0)
                {
                    name = tmp->name;
                    printf("%s: %s\n", name, tmp->description);
                    tmp = alldevs->next;
                }
                else
                {
                    tmp = NULL;
                }
            }
            mydev = alldevs->name;
        }
        printf("Utilisation de l'interface %s\n", mydev);
    }
    else
    {
        // analyse hors ligne: fichier spécifié
        printf("Analyse hors ligne\n");
        printf("Ouverture du fichier %s...\n", filepath);
        if ((fileflux = fopen(filepath, "r")) == NULL)
        {
            fprintf(stderr, "Erreur: ouverture du fichier %s impossible\n", filepath);
            exit(EXIT_FAILURE);
        }
    }

    // programme se termine avec SIGINT
    if(analyse(mydev, fileflux, verbosite) == ERROR)
    {
        fprintf(stderr, "Erreur: analyse échouée.\n");
        exit(EXIT_FAILURE);
    }

    printf("\nSIGINT reçu\n");
    printf("\nFin de l'analyse.\n");
    if(oflag) 
        fclose(fileflux);
    else 
        pcap_freealldevs(alldevs);        
    exit(EXIT_SUCCESS);
}