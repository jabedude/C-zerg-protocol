CC=gcc
CFLAGS=-Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline -lm

debug: CFLAGS += -DDEBUG -g
debug: all

all: decode encode

decode: decode.c zerg.o
	$(CC) $(CFLAGS) decode.c obj/zerg.o -o bin/$@

zerg.o: lib/zerg.c
	$(CC) $(CFLAGS) $< -c -o obj/zerg.o

encode: encode.c pcap.o
	$(CC) $(CFLAGS) encode.c obj/pcap.o -o bin/$@

pcap.o: lib/pcap.c
	$(CC) $(CFLAGS) $< -c -o obj/pcap.o
clean:
	rm -f bin/* obj/* test.pcap
