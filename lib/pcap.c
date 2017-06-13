#include <byteswap.h>
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

void write_gps(FILE *pfp, ZergHeader_t *zh, ZergGpsPayload_t *zgp)
{
    PcapPackHeader_t pack = (const PcapPackHeader_t) {0};
    EthHeader_t eth = (const EthHeader_t) {0};
    IpHeader_t ip = (const IpHeader_t) {0};
    UdpHeader_t udp = (const UdpHeader_t) {0};

    pack.recorded_len = sizeof(eth) + sizeof(ip) + sizeof(udp) + sizeof(ZergHeader_t) + sizeof(ZergGpsPayload_t);

    eth.eth_type = htons(0x0800);

    ip.ip_vhl = 0x45;
    ip.ip_len = htons(sizeof(ip) + sizeof(udp) + sizeof(ZergHeader_t) + sizeof(ZergGpsPayload_t));

    udp.uh_dport = htons(ZERG_DST_PORT);
    udp.uh_ulen = htons(sizeof(udp) + + sizeof(ZergHeader_t) + sizeof(ZergGpsPayload_t));
    /* EVERYTHING ABOVE THIS ARE INITIALIZERS */

    write_pcap(pfp);
    fwrite(&pack, sizeof(pack), 1, pfp);
    fwrite(&eth, sizeof(eth), 1, pfp);
    fwrite(&ip, sizeof(ip), 1, pfp);
    fwrite(&udp, sizeof(udp), 1, pfp);
    fwrite(zh, sizeof(ZergHeader_t), 1, pfp);
    fwrite(zgp, sizeof(ZergGpsPayload_t), 1, pfp);
    return;
}

void read_input(FILE *fp, FILE *pfp)
{
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

    while (fgets(line, MAX_LINE_SIZE, fp)) {
        if (sscanf(line, "Version : %hhu", &zerg_version))
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
            return; /*TODO: FP might not be at the end of this packet. test for asterik for next encode target*/
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
            return;
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
                if (i == 1)
                    (void) sscanf(line, "Move %hu m at bearing %f", &param_one, &param_two.f);
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
                return;
            }
            return;
        }
    }
    return;
}
