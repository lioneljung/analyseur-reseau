#include <stdio.h>

void afficherDNSsynthe(char *appdump)
{
    printf("DNS: \t\t");
    printf("%c\n", appdump[0]);
}

void afficherDNScomplet(char *appdump)
{
    printf("DNS\n");
    printf("%s\n", appdump);
}