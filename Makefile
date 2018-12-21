CFLAGS = -Wall -Wextra -lpcap -g
CC = gcc
OBJECTS = utils.o analyse.o affichage.o ipv6.o dns.o applicatif.o bootp.o
HEADER = utils.h defs.h utils.h affichage.h ipv6.h dns.h applicatif.h bootp.h
EXEC = analyseur

all: main.c $(OBJECTS) $(HEADER)
	$(CC) $< $(OBJECTS) $(CFLAGS) -o $(EXEC)

%.o: %.c
	$(CC) -c $< $(CFLAGS)

clean:
	rm $(OBJECTS)
	rm $(EXEC)