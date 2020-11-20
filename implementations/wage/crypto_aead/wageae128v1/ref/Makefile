CC=gcc 
NISTGCCFLAGS=-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2 
LFLAGS=-lm

all:wage_1
wage_1:wage

wage: genkat_aead.c encrypt.c wage.c
	$(CC) $(NISTGCCFLAGS) -o $@ $^ $(LFLAGS)

.PHONY: clean
clean: 
	-rm wage
