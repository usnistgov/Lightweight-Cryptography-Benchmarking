CC=gcc
CFLAGES=-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2 -DPC
OBJS=genkat_aead_hash.o photon.o encrypt.o hash.o common.o

all: table

table: $(OBJS)
	$(CC) -o table $(OBJS) $(CFLAGES)

genkat_aead_hash.o: ../../../genkat_aead_hash.c
	$(CC) -c ../../../genkat_aead_hash.c $(CFLAGES) -I./

encrypt.o: encrypt.c
	$(CC) -o encrypt.o -c encrypt.c $(CFLAGES) -I../../../

hash.o: hash.c
	$(CC) -o hash.o -c hash.c $(CFLAGES) -I../../../

common.o: common.c
	$(CC) -o common.o -c common.c $(CFLAGES) -I../../../

photon.o: photon.c
	$(CC) -c photon.c $(CFLAGES)

.PHONY : clean

clean :
	rm $(OBJS)