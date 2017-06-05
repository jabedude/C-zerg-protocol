#include <stdio.h>

#include "lib/pcap.h"

int main(int argc, char **argv)
{
    FILE *fp;
    PcapHeader_t pcap;
    PcapPackHeader_t pcap_pack;
    EthHeader_t eth;
    IpHeader_t ip;
    UdpHeader_t udp;

    /* Usage/ args check */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    fp = fopen(argv[1], "rb");

    fread(&pcap, sizeof(pcap), 1, fp);
    if (pcap.magic_num == 0xa1b2c3d4) {
        printf("DEBUG: This is a pcap.\n");
        printf("DEBUG: PCAP MAGIC NUM IS %x\n", pcap.magic_num);
        printf("DEBUG: PCAP VERSION NUMBER IS %u.%u\n", pcap.version_major, pcap.version_minor);
    } else {
        fprintf(stderr, "Please supply a valid pcap file.\n");
        return 1;
    }

    fread(&pcap_pack, sizeof(pcap_pack), 1, fp);
    printf("DEBUG: PACKET EPOCH IS %u\n", pcap_pack.epoch);
    printf("DEBUG: PACKET DATA LENGTH IS %u\n", pcap_pack.recorded_len);
    printf("DEBUG: PACKET LENGTH IS %u\n", pcap_pack.orig_len);

    fread(&eth, sizeof(eth), 1, fp);
    printf("DEBUG: ETH DEST HOST IS %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", 
                                            eth.eth_dhost[0],
                                            eth.eth_dhost[1],
                                            eth.eth_dhost[2],
                                            eth.eth_dhost[3],
                                            eth.eth_dhost[4],
                                            eth.eth_dhost[5]);
    printf("DEBUG: ETH SRC HOST IS %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", 
                                            eth.eth_shost[0],
                                            eth.eth_shost[1],
                                            eth.eth_shost[2],
                                            eth.eth_shost[3],
                                            eth.eth_shost[4],
                                            eth.eth_shost[5]);
    printf("DEBUG: ETHERTYPE IS: 0x%.2x\n", eth.eth_type);

    fread(&ip, sizeof(ip), 1, fp);
    printf("DEBUG: IP VERSION/HL is 0x%x\n", ip.ip_vhl);
    printf("DEBUG: IP TOTAL LEN is %x\n", ip.ip_len);

    fread(&udp, sizeof(udp), 1, fp);
    printf("DEBUG: UDP DEST PORT IS is 0x%x\n", ntohs(udp.uh_dport));
    printf("DEBUG: UDP LENGTH IS is %u\n", ntohs(udp.uh_ulen));

    fclose(fp);
    return 0;
}
