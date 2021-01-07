src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc
CFLAGS = -Os
LDFLAGS = -lm

all: build run

build: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)
run:
	./build

.PHONY: clean
clean:
	rm -f $(obj) build
