CC=gcc 
GCCFLAGS =-std=c99 -Wall -Wextra -Wshadow -fsanitize=address -O2 
#NISTGCCFLAGS =-std=c99 -Wall -Wextra -Wshadow -fsanitize=address undefined -O2 
#GCCFLAGS = -c -Wall
LFLAGS=-lm
ROOTDIR = .
SRCDIR = $(ROOTDIR)/src

all: spoc128_1

spoc128_1: spoc128

spoc128: genkat_aead.c encrypt.c sliscp_light192.c
	$(CC) $(GCCFLAGS) -o $@ $^ $(LFLAGS)

.PHONY: clean

clean: 
	-rm spoc128 
