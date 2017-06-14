#include <stdio.h>
#include <arpa/inet.h>

#include "lib/pcap.h"
#include "lib/zerg.h"

int main(int argc, char **argv)
{
    FILE *fp;
    long file_len, packet_end;
    int packet_num;
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
    if (!fp) {
        fprintf(stderr, "%s: Error opening file.\n", argv[0]);
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    file_len = ftell(fp);
    rewind(fp);

    fread(&pcap, sizeof(pcap), 1, fp);
    if (pcap.magic_num == 0xa1b2c3d4) {
#ifdef DEBUG
        printf("DEBUG: This is a pcap.\n");
        printf("DEBUG: PCAP MAGIC NUM IS %x\n", pcap.magic_num);
        printf("DEBUG: PCAP VERSION NUMBER IS %u.%u\n", pcap.version_major, pcap.version_minor);
        printf("DEBUG: FILE LENGTH IS %ld\n", file_len);
#endif
    } else {
        fprintf(stderr, "Please supply a valid pcap file.\n");
        fclose(fp);
        return 1;
    }

    packet_num = 1;
    while (ftell(fp) < file_len) {
        fread(&pcap_pack, sizeof(pcap_pack), 1, fp);
        printf("*** Packet %d ***\n", packet_num);
        packet_end = pcap_pack.recorded_len + ftell(fp);
#ifdef DEBUG
        printf("DEBUG: PACKET EPOCH IS %u\n", pcap_pack.epoch);
        printf("DEBUG: PACKET DATA LENGTH IS %u\n", pcap_pack.recorded_len);
        printf("DEBUG: PACKET LENGTH IS %u\n", pcap_pack.orig_len);
        printf("DEBUG: PACKET DATA LENGTH IS %u\n", pcap_pack.recorded_len);
        printf("DEBUG: PACKET END SHOULD BE %lu\n", packet_end);
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
        printf("Version : %x\n", zh.zh_vt >> 4);
        printf("Sequence : %u\n", ntohl(zh.zh_seqid));
        printf("From : %d\n", ntohs(zh.zh_src));
        printf("To : %d\n", ntohs(zh.zh_dest));

        if ((zh.zh_vt & 0xFF) == 0x10) {
            z_msg_parse(fp, &zh);
        } else if ((zh.zh_vt & 0xFF) == 0x11) {
            z_status_parse(fp, &zh);
        } else if ((zh.zh_vt & 0xFF) == 0x12) {
            z_cmd_parse(fp, &zh);
        } else if ((zh.zh_vt & 0xFF) == 0x13) {
            z_gps_parse(fp, &zh);
        } else {
            fprintf(stderr, "%s: error reading psychic capture.\n", argv[0]);
        }
#ifdef DEBUG
        printf("DEBUG: FP IS AT %lu\n", ftell(fp));
#endif
        packet_num++;
        fseek(fp, packet_end, SEEK_SET);

    }
    fclose(fp);
    return 0;
}
