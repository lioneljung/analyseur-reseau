CFLAGS = -Wall -Wextra -lpcap -g
CC = gcc
OBJECTS = utils.o analyse.o affichage.o \
	ipv6.o dns.o applicatif.o
EXEC = analyseur

all: main.c $(OBJECTS)
	$(CC) $< $(OBJECTS) $(CFLAGS) -o $(EXEC)

%.o: %.c
	$(CC) -c $< $(CFLAGS)

clean:
	rm $(OBJECTS)
	rm $(EXEC)