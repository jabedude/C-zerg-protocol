CC=gcc
CFLAGS=-Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline

all: decode encode

decode: decode.c
	$(CC) $(CFLAGS) $< -o bin/$@

encode: encode.c
	$(CC) $(CFLAGS) $< -o bin/$@

clean:
	rm -f bin/*
