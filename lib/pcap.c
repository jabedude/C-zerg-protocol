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

void write_stat(FILE *pfp, ZergHeader_t *zh, ZergStatPayload_t *zsp, char *name)
{
    PcapPackHeader_t pack = (const PcapPackHeader_t) {0};
    EthHeader_t eth = (const EthHeader_t) {0};
    IpHeader_t ip = (const IpHeader_t) {0};
    UdpHeader_t udp = (const UdpHeader_t) {0};

    pack.recorded_len = sizeof(eth) + sizeof(ip) + sizeof(udp) +sizeof(ZergHeader_t) + sizeof(ZergStatPayload_t) + strlen(name);

    eth.eth_type = htons(0x0800);

    ip.ip_vhl = 0x45;
    ip.ip_len = htons(sizeof(ip) + sizeof(udp) + sizeof(ZergHeader_t) + sizeof(ZergStatPayload_t) + strlen(name));

    udp.uh_dport = htons(ZERG_DST_PORT);
    udp.uh_ulen = htons(sizeof(udp) + + sizeof(ZergHeader_t) + sizeof(ZergStatPayload_t) + strlen(name));
    /* EVERYTHING ABOVE THIS ARE INITIALIZERS */

    write_pcap(pfp);
    fwrite(&pack, sizeof(pack), 1, pfp);
    fwrite(&eth, sizeof(eth), 1, pfp);
    fwrite(&ip, sizeof(ip), 1, pfp);
    fwrite(&udp, sizeof(udp), 1, pfp);
    fwrite(zh, sizeof(ZergHeader_t), 1, pfp);
    fwrite(zsp, sizeof(ZergStatPayload_t), 1, pfp);
    fwrite(name, sizeof(char), strlen(name), pfp);
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
    union {
        uint32_t b;
        float f;
    } fto32;
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

    rewind(fp); /* Status */
    if ((fscanf(fp, "Version : %hhu\nSequence : %u\nFrom : %hu\nTo : %hu\nHP : %u\nMax-HP : %u\nType : %[^\n]\nArmor : %hhu\nSpeed(m/s) : %f\nName : %[^\n]", &zerg_version, &zerg_sequence, &zerg_src, &zerg_dst, &zerg_hp, &zerg_max_hp, str, &zerg_armor, &fto32.f, name)) == 10) {

        printf("DEBUG: THIS IS A STATUS PACKET\nVER IS %d\nSEQ IS %d\nSRC IS %d\nDST IS %d\nHP IS %d\nMAX-HP IS %d\nTYPE IS %s\nARMOR IS %d\nSPEED IS %lf\nNAME IS %s\n", zerg_version, zerg_sequence, zerg_src, zerg_dst, zerg_hp, zerg_max_hp, str, zerg_armor, fto32.f, name);

        uint32_t len = strlen(name) + 12;
        len += ZERG_SIZE;
        zh.zh_len[0] = (len >> 16) & 0xFF;
        zh.zh_len[1] = (len >> 8) & 0xFF;
        zh.zh_len[2] = len & 0xFF;
        zh.zh_vt = 0x11;
        zh.zh_src = htons(zerg_src);
        zh.zh_dest = htons(zerg_dst);
        zh.zh_seqid = htonl(zerg_sequence);

        ZergStatPayload_t zsp = (const ZergStatPayload_t) {0};
        ZergBreed_t breeds[] = {
            {0, "Overmind"}, {1, "Larva"},
            {2, "Cerebrate"}, {3, "Overlord"},
            {4, "Queen"}, {5, "Drone"},
            {6, "Zergling"}, {7, "Lurker"},
            {8, "Broodling"}, {9, "Hydralisk"},
            {10, "Guardian"}, {11, "Scourge"},
            {12, "Ultralisk"}, {13, "Mutalisk"},
            {14, "Defiler"}, {15, "Devourer"},
        };

        zsp.zsp_hp[0] = (zerg_hp >> 16) & 0xFF;
        zsp.zsp_hp[1] = (zerg_hp >> 8) & 0xFF;
        zsp.zsp_hp[2] = zerg_hp & 0xFF;
        zsp.zsp_armor = zerg_armor;
        zsp.zsp_maxhp[0] = (zerg_max_hp >> 16) & 0xFF;
        zsp.zsp_maxhp[1] = (zerg_max_hp >> 8) & 0xFF;
        zsp.zsp_maxhp[2] = zerg_max_hp & 0xFF;
        for (int i = 0; i < 16; i++) {
            if (!strcmp(breeds[i].breed, str)) {
                zsp.zsp_ztype = i;
                break;
            }
            i++;
        }
        zsp.zsp_speed = htonl(fto32.b);
        write_stat(pfp, &zh, &zsp, name);
    }

    rewind(fp); /* Command */
    if ((fscanf(fp, "Version : %hhu\nSequence : %u\nFrom : %hu\nTo : %hu\n%[^\n]", &zerg_version, &zerg_sequence, &zerg_src, &zerg_dst, str)) == 5) {

        printf("DEBUG: THIS IS A COMMAND PACKET\nVER IS %d\nSEQ IS %d\nSRC IS %d\nDST IS %d\nCOMMAND IS %s\n",
                zerg_version, zerg_sequence, zerg_src, zerg_dst, str);

        ZergCmdPayload_t zcp = (const ZergCmdPayload_t) {0};
        ZergCommand_t cmds[] = {
            {0, "GET_STATUS"}, {1, "GOTO"},
            {2, "GET_GPS"}, {3, "NONE"},
            {4, "RETURN"}, {5, "SET_GROUP"},
            {6, "STOP"}, {7, "REPEAT"},
        };
        uint32_t len = 2;
        len += ZERG_SIZE;
        zh.zh_len[0] = (len >> 16) & 0xFF;
        zh.zh_len[1] = (len >> 8) & 0xFF;
        zh.zh_len[2] = len & 0xFF;
        zh.zh_vt = 0x12;
        zh.zh_src = htons(zerg_src);
        zh.zh_dest = htons(zerg_dst);
        zh.zh_seqid = htonl(zerg_sequence);

        int i;
        for (i = 0; i < 16; i++) {
            if (!strcmp(cmds[i].cmd, str)) {
                zcp.zcp_command = htons(i);
                break;
            }
            i++;
        }
        if (i % 2 == 0) {
            /* No parameters passed */
            write_cmd(pfp, &zh, &zcp);
        } else {
            /* Params passed */
        }
    }
    return;
}

void write_cmd(FILE *pfp, ZergHeader_t *zh, ZergCmdPayload_t *zcp)
{
    PcapPackHeader_t pack = (const PcapPackHeader_t) {0};
    EthHeader_t eth = (const EthHeader_t) {0};
    IpHeader_t ip = (const IpHeader_t) {0};
    UdpHeader_t udp = (const UdpHeader_t) {0};

    pack.recorded_len = sizeof(eth) + sizeof(ip) + sizeof(udp) + sizeof(ZergHeader_t) + sizeof(ZergCmdPayload_t);

    eth.eth_type = htons(0x0800);

    ip.ip_vhl = 0x45;
    ip.ip_len = htons(sizeof(ip) + sizeof(udp) + sizeof(ZergHeader_t) + sizeof(ZergCmdPayload_t));

    udp.uh_dport = htons(ZERG_DST_PORT);
    udp.uh_ulen = htons(sizeof(udp) + + sizeof(ZergHeader_t) + sizeof(ZergCmdPayload_t));
    /* EVERYTHING ABOVE THIS ARE INITIALIZERS */

    write_pcap(pfp);
    fwrite(&pack, sizeof(pack), 1, pfp);
    fwrite(&eth, sizeof(eth), 1, pfp);
    fwrite(&ip, sizeof(ip), 1, pfp);
    fwrite(&udp, sizeof(udp), 1, pfp);
    fwrite(zh, sizeof(ZergHeader_t), 1, pfp);
    fwrite(zcp, sizeof(ZergCmdPayload_t), 1, pfp);
    return;
}
