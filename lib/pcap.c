#include <stdio.h>

#include "pcap.h"

void write_packet(FILE *fp)
{
    PcapHeader_t pcap;

    pcap.magic_num = 0xa1b2c3d4;
    pcap.version_major = 2;
    pcap.version_minor = 4;
    pcap.thiszone = 0;
    pcap.sigfigs = 0;
    pcap.snaplen = 0;
    pcap.network = 1;

    fwrite(&pcap, sizeof(pcap), 1, fp);
    return;
}
