#include <stdio.h>

#include "lib/pcap.h"

int main(int argc, char **argv)
{
    FILE *fp;
    PcapHeader_t pcap;

    /* Usage/ args check */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    fp = fopen(argv[1], "rb");
    fread(&pcap, sizeof(pcap), 1, fp);
    fclose(fp);
    printf("DEBUG: PCAP MAGIC NUM IS %x\n", pcap.magic_num);

    if (pcap.magic_num == 0xa1b2c3d4) {
        printf("DEBUG: This is a pcap.\n");
    } else {
        fprintf(stderr, "Please supply a valid pcap file.\n");
        return 1;
    }

    return 0;
}
