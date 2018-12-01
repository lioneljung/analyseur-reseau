CFLAGS = -Wall -Wextra -Werror -lpcap -g
CC = gcc
OBJECTS = utils.o analyse.o affichage.o
EXEC = analyseur

all: main.c $(OBJECTS)
	$(CC) $< $(OBJECTS) $(CFLAGS) -o $(EXEC)

%.o: %.c
	$(CC) -c $< $(CFLAGS)

clean:
	rm $(OBJECTS)
	rm $(EXEC)