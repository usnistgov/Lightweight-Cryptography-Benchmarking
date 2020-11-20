.PHONY: clean

CC=gcc
CFLAGS=-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2

all: hash aead

aead: subterranean_mem_compact.c crypto_aead.c genkat_aead.c
	$(CC) $(CFLAGS) -o genkat_aead subterranean_mem_compact.c crypto_aead.c genkat_aead.c

hash: subterranean_mem_compact.c crypto_hash.c genkat_hash.c
	$(CC) $(CFLAGS) -o genkat_hash subterranean_mem_compact.c crypto_hash.c genkat_hash.c

clean:
	@echo "Cleaning up..."
	rm -f "genkat_hash"
	rm -f "LWC_HASH_KAT_256.txt"
	rm -f "genkat_aead"
	rm -f "LWC_AEAD_KAT_128_128.txt"
	@echo "Cleaning done."