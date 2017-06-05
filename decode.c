#include <stdio.h>
#include <arpa/inet.h>

#include "lib/pcap.h"

int main(int argc, char **argv)
{
    FILE *fp;
    PcapHeader_t pcap;
    PcapPackHeader_t pcap_pack;
    EthHeader_t eth;
    IpHeader_t ip;
    UdpHeader_t udp;
    ZergHeader_t zh;

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
#ifdef DEBUG
    printf("DEBUG: PACKET EPOCH IS %u\n", pcap_pack.epoch);
    printf("DEBUG: PACKET DATA LENGTH IS %u\n", pcap_pack.recorded_len);
    printf("DEBUG: PACKET LENGTH IS %u\n", pcap_pack.orig_len);
#endif

    fread(&eth, sizeof(eth), 1, fp);
#ifdef DEBUG
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
#endif

    fread(&ip, sizeof(ip), 1, fp);
#ifdef DEBUG
    printf("DEBUG: IP VERSION/HL is 0x%x\n", ip.ip_vhl);
    printf("DEBUG: IP TOTAL LEN is %x\n", ip.ip_len);
    printf("DEBUG: SOURCE IP is %s\n", inet_ntoa(ip.ip_src));
    printf("DEBUG: DEST IP is %s\n", inet_ntoa(ip.ip_dst));
#endif

    fread(&udp, sizeof(udp), 1, fp);
#ifdef DEBUG
    printf("DEBUG: UDP DEST PORT IS is 0x%x\n", ntohs(udp.uh_dport));
    printf("DEBUG: UDP LENGTH IS is %u\n", ntohs(udp.uh_ulen));
#endif

    fread(&zh, sizeof(zh), 1, fp);
    printf("Version: %x\n", zh.zh_vt >> 4);
    printf("Sequence: %d\n", ntohl(zh.zh_seqid));
    printf("From: %d\n", ntohs(zh.zh_src));
    printf("To: %d\n", ntohs(zh.zh_dest));

    if ((zh.zh_vt & 0xFF) == 0x10) /* TODO: Create macro for these mask operations */
        printf("DEBUG: ZERG V 1 // TYPE 0\n");
    else if ((zh.zh_vt & 0xFF) == 0x11)
        printf("DEBUG: ZERG V 1 // TYPE 1\n");
    else if ((zh.zh_vt & 0xFF) == 0x12)
        printf("DEBUG: ZERG V 1 // TYPE 2\n");
    else if ((zh.zh_vt & 0xFF) == 0x13)
        printf("DEBUG: ZERG V 1 // TYPE 3\n");
    else
        fprintf(stderr, "%s: error reading psychic capture.\n", argv[0]);

    fclose(fp);
    return 0;
}
