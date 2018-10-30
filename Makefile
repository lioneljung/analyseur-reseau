CFLAGS = -Wall -Wextra -Werror -lpcap
CC = gcc
OBJECTS = 

all: main.c $(OBJECTS)
	$(CC) $< $(CFLAGS) -o main

%.o: %.c
	$(CC) -c $< $(CFLAGS)