#include <stdio.h>
#include <string.h>

#include "pcap.h"
#include "zerg.h"

void write_pcap(FILE *fp)
{
    PcapHeader_t pcap;
    /* TODO: FIX THIS */
    pcap.magic_num = 0xa1b2c3d4;
    pcap.version_major = 2;
    pcap.version_minor = 4;
    pcap.thiszone = 0;
    pcap.sigfigs = 0;
    pcap.snaplen = MAX_PACKET_CAPTURE;
    pcap.network = 1;

    fwrite(&pcap, sizeof(pcap), 1, fp);
    return;
}

void write_msg(FILE *pfp, ZergHeader_t *zh, char *msg)
{
    PcapPackHeader_t pack = (const PcapPackHeader_t) {0};
    EthHeader_t eth = (const EthHeader_t) {0};
    IpHeader_t ip = (const IpHeader_t) {0};
    UdpHeader_t udp = (const UdpHeader_t) {0};

    pack.recorded_len = sizeof(eth) + sizeof(ip) + sizeof(udp) + sizeof(ZergHeader_t) + strlen(msg);

    eth.eth_type = htons(0x0800);

    ip.ip_vhl = 0x45;
    ip.ip_len = htons(sizeof(ip) + sizeof(udp) + sizeof(ZergHeader_t) + strlen(msg));

    udp.uh_dport = htons(ZERG_DST_PORT);
    udp.uh_ulen = htons(sizeof(udp) + sizeof(ZergHeader_t) + strlen(msg));
    /* EVERYTHING ABOVE THIS ARE INITIALIZERS */

    write_pcap(pfp);
    fwrite(&pack, sizeof(pack), 1, pfp);
    fwrite(&eth, sizeof(eth), 1, pfp);
    fwrite(&ip, sizeof(ip), 1, pfp);
    fwrite(&udp, sizeof(udp), 1, pfp);
    fwrite(zh, sizeof(ZergHeader_t), 1, pfp);
    fwrite(msg, sizeof(char), strlen(msg), pfp);

    return;
}

void read_input(FILE *fp, FILE *pfp)
{
    uint8_t zerg_version;
    uint16_t zerg_src, zerg_dst;
    uint32_t zerg_sequence;
    ZergHeader_t zh;
    char str[MAX_LINE_SIZE];
    uint32_t zerg_hp;
    uint32_t zerg_max_hp;
    uint8_t zerg_armor;
    double zerg_speed;
    char name[MAX_LINE_SIZE];

    /* TODO: move below block to while loop down */
    if ((fscanf(fp, "Version : %hhu Sequence : %u From : %hu To : %hu Message : %[^\n]s",
            &zerg_version, &zerg_sequence, &zerg_src, &zerg_dst, str)) == 5) {
        printf("DEBUG: VERSION IS %u -- SEQUENCE IS %u -- SOURCE IS %u -- DESTINATION IS %u -- MESSAGE IS %s\n",
                zerg_version, zerg_sequence, zerg_src, zerg_dst, str);
        uint32_t len = strlen(str);
        len += ZERG_SIZE;
        zh.zh_len[0] = (len >> 16) & 0xFF;
        zh.zh_len[1] = (len >> 8) & 0xFF;
        zh.zh_len[2] = len & 0xFF;
        zh.zh_vt = 0x10;
        zh.zh_src = htons(zerg_src);
        zh.zh_dest = htons(zerg_dst);
        zh.zh_seqid = htonl(zerg_sequence);
        write_msg(pfp, &zh, str);
    }
    rewind(fp);
    if ((fscanf(fp, "Version : %hhu\nSequence : %u\nFrom : %hu\nTo : %hu\nHP : %u\nMax-HP : %u\nType : %[^\n]\nArmor : %hhu\nSpeed(m/s) : %lf\nName : %[^\n]", &zerg_version, &zerg_sequence, &zerg_src, &zerg_dst, &zerg_hp, &zerg_max_hp, str, &zerg_armor, &zerg_speed, name)) == 10) {

        printf("DEBUG: THIS IS A STATUS PACKET\nVER IS %d\nSEQ IS %d\nSRC IS %d\nDST IS %d\nHP IS %d\nMAX-HP IS %d\nTYPE IS %s\nARMOR IS %d\nSPEED IS %lf\nNAME IS %s\n", zerg_version, zerg_sequence, zerg_src, zerg_dst, zerg_hp, zerg_max_hp, str, zerg_armor, zerg_speed, name);
    }

    return;
}
