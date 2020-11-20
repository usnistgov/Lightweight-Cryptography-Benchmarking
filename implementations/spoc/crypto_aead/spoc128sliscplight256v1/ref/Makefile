CC=gcc 
NISTGCCFLAGS =-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2 
LFLAGS=-lm
ROOTDIR = .
SRCDIR = $(ROOTDIR)/src

all: spoc128_1

spoc128_1: spoc128

spoc128: genkat_aead.c encrypt.c sliscp_light256.c
	$(CC) $(NISTGCCFLAGS) -o $@ $^ $(LFLAGS)

.PHONY: clean

clean: 
	-rm spoc128 
