CC=gcc
CFLAGS=-Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline

all: decode encode

decode: decode.c zerg.o
	$(CC) $(CFLAGS) decode.c obj/zerg.o -o bin/$@

zerg.o: lib/zerg.c
	$(CC) $(CFLAGS) $< -c -o obj/zerg.o

encode: encode.c
	$(CC) $(CFLAGS) $< -o bin/$@

clean:
	rm -f bin/* obj/*
