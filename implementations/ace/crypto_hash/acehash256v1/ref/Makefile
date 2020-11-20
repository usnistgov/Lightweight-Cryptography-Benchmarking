CC=gcc 
NISTGCCFLAGS =-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2 
LFLAGS=-lm

all: acehash256_1 
#all:myacetest1

acehash256_1:acehash256
#myacetest1:myacetest

acehash256: genkat_hash.c hash.c ace.c
	$(CC) $(NISTGCCFLAGS) -o $@ $^ $(LFLAGS)

.PHONY: clean

clean: 
	-rm acehash256
