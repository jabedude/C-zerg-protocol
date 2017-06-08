#include <stdio.h>

#include "lib/pcap.h"

int main(int argc, char **argv)
{
    FILE *fp;
    FILE *pfp;

    if (argc != 3) { /* Usage check */
        fprintf(stderr, "Usage: %s <input file> <output pcap name>\n", argv[0]);
        return 1;
    }

    fp = fopen(argv[1], "rb");
    if (!fp) { /* Error handling */
        fprintf(stderr, "%s: Error reading input file.\n", argv[0]);
        return 1;
    }
    pfp = fopen(argv[2], "wb");
    if (!pfp) { /* Error handling */
        fprintf(stderr, "%s: Error opening pcap file.\n", argv[0]);
        return 1;
    }

    read_input(fp, pfp);

    fclose(fp);
    fclose(pfp);
    return 0;
}
