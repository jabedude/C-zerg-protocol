SRCS=decode.c
CC=gcc
CFLAGS=-Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline

all: decode

decode: $(SRCS)
	$(CC) $(CFLAGS) $< -o bin/$@

clean:
	rm -f bin/*
