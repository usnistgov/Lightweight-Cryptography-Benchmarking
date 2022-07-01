CC=gcc
CFLAGES=-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -static-libasan -fuse-ld=gold -O3 -DPC
OBJS=genkat_hash.o hash.o photon.o timing_hash.o
REFOBJS=genkat_hash.o photon.o hash.o
TIMEOBJS=timing_hash.o photon.o hash.o

all: bitslice timingbitslice

bitslice: $(REFOBJS)
	$(CC) -o bitslice $(REFOBJS) $(CFLAGES)

timingbitslice: $(TIMEOBJS)
	$(CC) -o timingbitslice $(TIMEOBJS) $(CFLAGES) -lm

genkat_hash.o: ../../../genkat_hash.c
	$(CC) -c ../../../genkat_hash.c $(CFLAGES) -I./

timing_hash.o: ../../../timing_hash.c
	$(CC) -c ../../../timing_hash.c $(CFLAGES) -I./ -lm

hash.o: hash.c
	$(CC) -o hash.o -c hash.c $(CFLAGES) -I../../../

photon.o: photon.c
	$(CC) -c photon.c $(CFLAGES)

.PHONY : clean

clean :
	rm $(OBJS) $(TIMEOBJS)