#include <stdio.h>

#include "lib/pcap.h"

int main(int argc, char **argv)
{
    FILE *fp;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <output file name>\n", argv[0]);
        return 1;
    }

    fp = fopen(argv[1], "wb");
    write_packet(fp);

    fclose(fp);
    return 0;
}
