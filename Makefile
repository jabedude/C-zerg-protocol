CC=gcc
CFLAGS=-Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline

all: decode encode

decode: decode.c zerg.o
	$(CC) $(CFLAGS) decode.c obj/zerg.o -o bin/$@ -lm

zerg.o: lib/zerg.c
	$(CC) $(CFLAGS) $< -c -o obj/zerg.o -lm

encode: encode.c pcap.o
	$(CC) $(CFLAGS) encode.c obj/pcap.o -o bin/$@ -lm

pcap.o: lib/pcap.c
	$(CC) $(CFLAGS) $< -c -o obj/pcap.o -lm

debug: CFLAGS += -DDEBUG -g -fstack-usage
debug: all

clean:
	rm -f bin/* obj/* test.pcap *.su .gdb_history
