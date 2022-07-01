CC=gcc
CFLAGES=-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -static-libasan -fuse-ld=gold -O3 -DPC
OBJS=genkat_aead.o photon.o encrypt.o
REFOBJS=genkat_aead.o photon.o encrypt.o
TIMEOBJS=timing_aead.o photon.o encrypt.o

all: bitslice timingbitslice

bitslice: $(REFOBJS)
	$(CC) -o bitslice $(REFOBJS) $(CFLAGES)

timingbitslice: $(TIMEOBJS)
	$(CC) -o timingbitslice $(TIMEOBJS) $(CFLAGES) -lm

genkat_aead.o: ../../../genkat_aead.c
	$(CC) -c ../../../genkat_aead.c $(CFLAGES) -I./

timing_aead.o: ../../../timing_aead.c
	$(CC) -c ../../../timing_aead.c $(CFLAGES) -I./ -lm

encrypt.o: encrypt.c
	$(CC) -o encrypt.o -c encrypt.c $(CFLAGES) -I../../../

photon.o: photon.c
	$(CC) -c photon.c $(CFLAGES)

.PHONY : clean

clean :
	rm $(OBJS) $(TIMEOBJS)