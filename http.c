#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "defs.h"


void afficherHTTPsynthe(char *appdump)
{
    if (appdump == NULL)
        return;
    printf("HTTP: \t\t");
    while ((appdump[0] != '\n') && isprint(appdump[0]))
    {
        printf("%c", appdump[0]);
        appdump++;
    }
}

void afficherHTTPcomplet(char *appdump)
{
    int count = 0;
    if (appdump == NULL)
        return;
    printf("HTTP\n\t");
    while (appdump[0] != 0)
    {
        // 0x0D0A => saut à la ligne
        if ((appdump[0] == CR) && (appdump[1] == LF))
        {
            printf("\n");
            count = 0;
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
}
