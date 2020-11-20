CC=gcc 
NISTGCCFLAGS =-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2 
LFLAGS=-lm
ROOTDIR = .
SRCDIR = $(ROOTDIR)/src

all: spix_1

spix_1: spix

spix: genkat_aead.c encrypt.c sliscp_light256.c
	$(CC) $(NISTGCCFLAGS) -o $@ $^ $(LFLAGS)

.PHONY: clean

clean: 
	-rm spix 
