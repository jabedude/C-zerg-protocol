#include <stdio.h>

#include "lib/pcap.h"

int main(int argc, char **argv)
{
    FILE *fp;
    FILE *pfp;

    /* Argument check */
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input file> <output pcap name>\n", argv[0]);
        return 1;
    }

    fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "%s: Error reading input file.\n", argv[0]);
        return 1;
    }
    pfp = fopen(argv[2], "wb");
    if (!pfp) {
        fprintf(stderr, "%s: Error opening pcap file.\n", argv[0]);
        return 1;
    }

    /* Call to main encoding routine */
    read_input(fp, pfp);
#ifdef DEBUG
    printf("DEBUG: fp is now at %ld\n", ftell(fp));
#endif

    fclose(fp);
    fclose(pfp);
    return 0;
}
