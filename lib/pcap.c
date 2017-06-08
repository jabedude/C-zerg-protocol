#include <stdio.h>
#include <string.h>

#include "pcap.h"

void write_pcap(FILE *fp)
{
    PcapHeader_t pcap;
    /* TODO: FIX THIS */
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

void read_input(FILE *fp, FILE *pfp)
{
    uint8_t zerg_version;
    uint16_t zerg_src, zerg_dst;
    uint32_t zerg_sequence;
    ZergHeader_t zh;
    char msg[MAX_LINE_SIZE];

    if (fscanf(fp, "Version : %hhu Sequence : %u From : %hu To : %hu Message : %[^\n]s",
            &zerg_version, &zerg_sequence, &zerg_src, &zerg_dst, msg)) {
        printf("DEBUG: VERSION IS %u -- SEQUENCE IS %u -- SOURCE IS %u -- DESTINATION IS %u -- MESSAGE IS %s\n",
                zerg_version, zerg_sequence, zerg_src, zerg_dst, msg);
        uint32_t len = strlen(msg);
        len += ZERG_SIZE;
        zh.zh_len[0] = (len >> 16) & 0xFF;
        zh.zh_len[1] = (len >> 8) & 0xFF;
        zh.zh_len[2] = len & 0xFF;
        zh.zh_vt = 0x10;
        zh.zh_src = zerg_src;
        zh.zh_dest = zerg_dst;
        zh.zh_seqid = zerg_sequence;
        write_msg(pfp, &zh, msg);
    }

    return;
}

void write_msg(FILE *pfp, ZergHeader_t *zh, char *msg)
{
    PcapPackHeader_t pack;
    EthHeader_t eth;
    IpHeader_t ip;
    UdpHeader_t udp;

    write_pcap(pfp);
    fwrite(&pack, sizeof(pack), 1, pfp);
    fwrite(&eth, sizeof(eth), 1, pfp);
    fwrite(&ip, sizeof(ip), 1, pfp);
    fwrite(&udp, sizeof(udp), 1, pfp);
    fwrite(zh, sizeof(ZergHeader_t), 1, pfp);
    fwrite(msg, sizeof(char), strlen(msg), pfp);

    return;
}
