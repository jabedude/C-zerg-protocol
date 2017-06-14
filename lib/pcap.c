#include <byteswap.h>
#include <stdio.h>
#include <string.h>

#include "pcap.h"
#include "zerg.h"

/* STATIC TEMPLATES */
static const PcapHeader_t st_pcap = {0xa1b2c3d4, 2, 4, 0, 0, MAX_PACKET_CAPTURE, 1};
static const PcapPackHeader_t st_pack = {0x582b59dc, 0x000701d2, 0x00000000, 0x00000000};
static const EthHeader_t st_eth = {{0xea, 0x7e, 0xa7, 0xfa, 0x55, 0xc5}, {0xea, 0x7e, 0xa7, 0x8e, 0x16, 0x48}, 0x0008};
static const IpHeader_t st_ip = {0x45, 0x00, 0x0000, 0x0000, 0x00, 0x00, 0x11, 0x0000, {0x720f000a}, {0x3015000a}};
static const UdpHeader_t st_udp = {0x4281, 0xa70e, 0x0000, 0x0000};

void write_pcap(FILE *fp)
{
    fwrite(&st_pcap, sizeof(st_pcap), 1, fp);
    return;
}

void write_msg(FILE *pfp, ZergHeader_t *zh, char *msg)
{
    PcapPackHeader_t pack = st_pack;
    IpHeader_t ip = st_ip;
    UdpHeader_t udp = st_udp;

    pack.recorded_len = sizeof(st_eth) + sizeof(ip) + sizeof(udp) + sizeof(ZergHeader_t) + strlen(msg);
    pack.orig_len = pack.recorded_len;

    ip.ip_len = htons(sizeof(ip) + sizeof(udp) + sizeof(ZergHeader_t) + strlen(msg));

    udp.uh_ulen = htons(sizeof(udp) + sizeof(ZergHeader_t) + strlen(msg));
    /* EVERYTHING ABOVE THIS ARE INITIALIZERS */

    fwrite(&pack, sizeof(pack), 1, pfp);
    fwrite(&st_eth, sizeof(st_eth), 1, pfp);
    fwrite(&ip, sizeof(ip), 1, pfp);
    fwrite(&udp, sizeof(udp), 1, pfp);
    fwrite(zh, sizeof(ZergHeader_t), 1, pfp);
    fwrite(msg, sizeof(char), strlen(msg), pfp);

    return;
}

void write_stat(FILE *pfp, ZergHeader_t *zh, ZergStatPayload_t *zsp, char *name)
{
    PcapPackHeader_t pack = st_pack;
    IpHeader_t ip = st_ip;
    UdpHeader_t udp = st_udp;

    pack.recorded_len = sizeof(st_eth) +
                        sizeof(ip) +
                        sizeof(udp) +
                        sizeof(ZergHeader_t) +
                        sizeof(ZergStatPayload_t) +
                        strlen(name);
    pack.orig_len = pack.recorded_len;

    ip.ip_len = htons(sizeof(ip) + sizeof(udp) + sizeof(ZergHeader_t) + sizeof(ZergStatPayload_t) + strlen(name));

    udp.uh_ulen = htons(sizeof(udp) + + sizeof(ZergHeader_t) + sizeof(ZergStatPayload_t) + strlen(name));
    /* EVERYTHING ABOVE THIS ARE INITIALIZERS */

    fwrite(&pack, sizeof(pack), 1, pfp);
    fwrite(&st_eth, sizeof(st_eth), 1, pfp);
    fwrite(&ip, sizeof(ip), 1, pfp);
    fwrite(&udp, sizeof(udp), 1, pfp);
    fwrite(zh, sizeof(ZergHeader_t), 1, pfp);
    fwrite(zsp, sizeof(ZergStatPayload_t), 1, pfp);
    fwrite(name, sizeof(char), strlen(name), pfp);
    return;
}

void write_cmd(FILE *pfp, ZergHeader_t *zh, ZergCmdPayload_t *zcp)
{
    PcapPackHeader_t pack = st_pack;
    IpHeader_t ip = st_ip;
    UdpHeader_t udp = st_udp;

    pack.recorded_len = sizeof(st_eth) + sizeof(ip) + sizeof(udp) + sizeof(ZergHeader_t) + sizeof(ZergCmdPayload_t);
    pack.orig_len = pack.recorded_len;

    ip.ip_len = htons(sizeof(ip) + sizeof(udp) + sizeof(ZergHeader_t) + sizeof(ZergCmdPayload_t));

    udp.uh_ulen = htons(sizeof(udp) + + sizeof(ZergHeader_t) + sizeof(ZergCmdPayload_t));
    /* EVERYTHING ABOVE THIS ARE INITIALIZERS */

    fwrite(&pack, sizeof(pack), 1, pfp);
    fwrite(&st_eth, sizeof(st_eth), 1, pfp);
    fwrite(&ip, sizeof(ip), 1, pfp);
    fwrite(&udp, sizeof(udp), 1, pfp);
    fwrite(zh, sizeof(ZergHeader_t), 1, pfp);
    fwrite(zcp, sizeof(ZergCmdPayload_t), 1, pfp);
    return;
}

void write_gps(FILE *pfp, ZergHeader_t *zh, ZergGpsPayload_t *zgp)
{
    PcapPackHeader_t pack = st_pack;
    IpHeader_t ip = st_ip;
    UdpHeader_t udp = st_udp;

    pack.recorded_len = sizeof(st_eth) + sizeof(ip) + sizeof(udp) + sizeof(ZergHeader_t) + sizeof(ZergGpsPayload_t);
    pack.orig_len = pack.recorded_len;

    ip.ip_len = htons(sizeof(ip) + sizeof(udp) + sizeof(ZergHeader_t) + sizeof(ZergGpsPayload_t));

    udp.uh_ulen = htons(sizeof(udp) + + sizeof(ZergHeader_t) + sizeof(ZergGpsPayload_t));
    /* EVERYTHING ABOVE THIS ARE INITIALIZERS */

    fwrite(&pack, sizeof(pack), 1, pfp);
    fwrite(&st_eth, sizeof(st_eth), 1, pfp);
    fwrite(&ip, sizeof(ip), 1, pfp);
    fwrite(&udp, sizeof(udp), 1, pfp);
    fwrite(zh, sizeof(ZergHeader_t), 1, pfp);
    fwrite(zgp, sizeof(ZergGpsPayload_t), 1, pfp);
    return;
}

void read_input(FILE *fp, FILE *pfp)
{
    int pack_num;
    uint8_t zerg_version;
    uint16_t zerg_src, zerg_dst;
    uint32_t zerg_sequence;
    ZergHeader_t zh;
    char str[MAX_LINE_SIZE];
    char line[MAX_LINE_SIZE];
    uint32_t zerg_hp;
    uint32_t zerg_max_hp;
    uint8_t zerg_armor;
    union Fto32 {
        uint32_t b;
        int32_t i;
        float f;
    };
    union Fto32 stat_speed;
    char name[MAX_LINE_SIZE];
    union Dto64 {
        uint64_t b;
        double d;
    };
    union Dto64 dto64;
    union Dto64 latto64;
    union Fto32 altitude;
    union Fto32 bearing;
    union Fto32 speed;
    union Fto32 acc;

    write_pcap(pfp);

    while (fgets(line, MAX_LINE_SIZE, fp)) {
        if (sscanf(line, "*** Packet %d ***", &pack_num))
            printf("DEBUG: PACKET NUMBER IS %d\n", pack_num);
        else if (sscanf(line, "Version : %hhu", &zerg_version))
            printf("DEBUG: VERSION IS %u\n", zerg_version);
        else if (sscanf(line, "Sequence : %u", &zerg_sequence))
            printf("DEBUG: SEQUENCE IS %u\n", zerg_sequence);
        else if (sscanf(line, "From : %hu", &zerg_src))
            printf("DEBUG: SOURCE IS %u\n", zerg_src);
        else if (sscanf(line, "To : %hu", &zerg_dst))
            printf("DEBUG: DESTINATION IS %u\n", zerg_dst);
        else if (sscanf(line, "Message : %[^\n]", str)) {
            printf("DEBUG: MESSAGE IS %s\n", str);
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
            printf("DEBUG: fp is at %ld\n", ftell(fp));
        }
        else if (sscanf(line, "HP : %u", &zerg_hp)) {
            for (int i = 0; i < 5; i++) {
                fgets(line, MAX_LINE_SIZE, fp);
                (void) sscanf(line, "Max-HP : %u", &zerg_max_hp);
                (void) sscanf(line, "Type : %[^\n]", str);
                (void) sscanf(line, "Armor : %hhu", &zerg_armor);
                (void) sscanf(line, "Speed(m/s) : %f", &stat_speed.f);
                (void) sscanf(line, "Name : %[^\n]", name);
            }
            printf("DEBUG: THIS IS A STATUS PACKET\nVER IS %d\nSEQ IS %d\nSRC IS %d\nDST IS %d\nHP IS %d\nMAX-HP IS %d\nTYPE IS %s\nARMOR IS %d\nSPEED IS %lf\nNAME IS %s\n", zerg_version, zerg_sequence, zerg_src, zerg_dst, zerg_hp, zerg_max_hp, str, zerg_armor, stat_speed.f, name);

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
            ZergData_t breeds[] = {
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
                if (!strcmp(breeds[i].data, str)) {
                    zsp.zsp_ztype = i;
                    break;
                }
                i++;
            }
            zsp.zsp_speed = htonl(stat_speed.b);
            write_stat(pfp, &zh, &zsp, name);

            printf("DEBUG: fp is at %ld\n", ftell(fp));
            return;
        }
        else if (sscanf(line, "Longitude : %le deg", &dto64.d)) {
            for (int i = 0; i < 6; i++) {
                fgets(line, MAX_LINE_SIZE, fp);
                (void) sscanf(line, "Latitude : %le deg", &latto64.d);
                (void) sscanf(line, "Altitude : %e m", &altitude.f);
                (void) sscanf(line, "Bearing : %e deg", &bearing.f);
                (void) sscanf(line, "Speed : %e m/s", &speed.f);
                (void) sscanf(line, "Accuracy : %e m", &acc.f);
            }
            printf("DEBUG: THIS IS A GPS PACKET\nVER IS %d\nSEQ IS %d\nSRC IS %d\nDST IS %d\nLONG IS %6.4f\nLAT IS %6.4f\nALT IS %6.4f\nBEARING IS %6.4f\nSPEED IS %6.4f\nACCURACY IS %6.4f\n",
                    zerg_version, zerg_sequence, zerg_src, zerg_dst, dto64.d, latto64.d, altitude.f, bearing.f, speed.f, acc.f);
            ZergGpsPayload_t zgp = (const ZergGpsPayload_t) {0};

            uint32_t len = 32 + ZERG_SIZE;
            zh.zh_len[0] = (len >> 16) & 0xFF;
            zh.zh_len[1] = (len >> 8) & 0xFF;
            zh.zh_len[2] = len & 0xFF;
            zh.zh_vt = 0x13;
            zh.zh_src = htons(zerg_src);
            zh.zh_dest = htons(zerg_dst);
            zh.zh_seqid = htonl(zerg_sequence);

            zgp.zgp_long = bswap_64(dto64.b);
            zgp.zgp_lat = bswap_64(latto64.b);
            zgp.zgp_alt = htonl(altitude.b);
            zgp.zgp_bearing = htonl(bearing.b);
            zgp.zgp_speed = htonl(speed.b);
            zgp.zgp_acc = htonl(acc.b);
            write_gps(pfp, &zh, &zgp);
            printf("DEBUG: fp is at %ld\n", ftell(fp));
            //return;
        }
        else if (sscanf(line, "%[^\n]", str)) {
            printf("DEBUG: THIS IS A COMMAND PACKET\nVER IS %d\nSEQ IS %d\nSRC IS %d\nDST IS %d\nCOMMAND IS %s\n",
                    zerg_version, zerg_sequence, zerg_src, zerg_dst, str);
            ZergCmdPayload_t zcp = (const ZergCmdPayload_t) {0};
            ZergData_t cmds[] = {
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
                if (!strcmp(cmds[i].data, str)) {
                    zcp.zcp_command = htons(i);
                    break;
                }
            }
            if (i % 2 == 0) {
                /* No parameters passed */
                write_cmd(pfp, &zh, &zcp);
                printf("DEBUG: fp is at %ld\n", ftell(fp));
            } else {
                /* Params passed */
                uint32_t len = 8;
                len += ZERG_SIZE;
                zh.zh_len[0] = (len >> 16) & 0xFF;
                zh.zh_len[1] = (len >> 8) & 0xFF;
                zh.zh_len[2] = len & 0xFF;
                uint16_t param_one = 0;
                //uint32_t param_two = 0;
                union Fto32 param_two;
                fgets(line, MAX_LINE_SIZE, fp);
                if (i == 1) {
                    (void) sscanf(line, "Move %hu m at bearing %f", &param_one, &param_two.f);
                    zcp.zcp_param_one = htons(param_one);
                    zcp.zcp_param_two = htonl(param_two.b);
                }
                else if (i == 5) {
                    (void) sscanf(line, "%s to/from group ID %d", str, &param_two.i);
                    if (!strcmp(str, "ADD"))
                        param_one = 1;
                    zcp.zcp_param_one = htons(param_one);
                    zcp.zcp_param_two = ~param_two.i + 1; /*TODO: POSSIBLE HACK */
                }
                else if (i == 7) {
                    (void) sscanf(line, "Re-send %u", &param_two.b);
                    zcp.zcp_param_one = htons(param_one);
                    zcp.zcp_param_two = htonl(param_two.b);
                }

                printf("DEBUG: PARAM ONE IS %d\n", param_one);
                printf("DEBUG: PARAM TWO IS %f\n", param_two.f);
                write_cmd(pfp, &zh, &zcp);
                printf("DEBUG: fp is at %ld\n", ftell(fp));
                //return; /* TODO: WHY ARE THREE RETURNS NEEDED?? */
            }
            //return;
        }
    }
    return;
}
