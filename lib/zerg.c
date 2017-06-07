#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "zerg.h"
#include "pcap.h"

double ieee_convert(uint32_t num)
{
    uint8_t sign, exponent;
    uint32_t mantisa;
    double result = 0;

    sign = num >> 31;
    exponent = (num >> 23 & 0xFF) - 127;
    mantisa = num & 0x7FFFFF;

    result = (mantisa *pow(2, -23)) + 1;
    result *= pow(1, sign) * pow(2, exponent);

    return result;
}

void z_msg_parse(FILE *fp, ZergHeader_t *zh)
{
    int len = 0;
    char *msg;

    printf("DEBUG: TOTAL LEN IS %.2x%.2x%.2x\n", zh->zh_len[0], zh->zh_len[1], zh->zh_len[2]);

    len = NTOH3(zh->zh_len);
    len -= ZERG_SIZE;
    printf("DEBUG: PAYLOAD IS %d\n", len);

    msg = (char *) malloc(sizeof(char) * len);
    fread(msg, sizeof(char), len, fp);
    printf("DEBUG: MSG IS: ");
    for (int i = 0; i < len; i++) {
        printf("%c", msg[i]);
    }
    putchar('\n');

    free(msg);
    return;
}

void z_status_parse(FILE *fp, ZergHeader_t *zh)
{
    int len = 0;
    int hp = 0;
    unsigned int max_hp = 0;
    char *name;
    ZergStatPayload_t zsp;
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

    len = NTOH3(zh->zh_len);
    len -= ZERG_SIZE;
    printf("DEBUG: PAYLOAD IS %d\n", len);

    fread(&zsp, sizeof(zsp), 1, fp);
    hp = NTOH3(zsp.zsp_hp);
    max_hp = NTOH3(zsp.zsp_maxhp);
    printf("DEBUG: HP IS: %d\n", hp);
    printf("DEBUG: ZERG TYPE IS: %d\n", zsp.zsp_ztype);
    printf("DEBUG: NAME LENGTH IS: %d\n", len - ZERG_STAT_LEN);
    printf("HP : %d/%u\n", hp, max_hp);
    printf("Type: %s\n", breeds[zsp.zsp_ztype].breed);
    printf("Armor: %u\n", zsp.zsp_armor);
    printf("Speed: %fm/s\n", ieee_convert(ntohl(zsp.zsp_speed))); /* TODO: Drop trailing zeros. try sprintf() */
    name = (char *) malloc(sizeof(char) * len - ZERG_STAT_LEN);
    fread(name, sizeof(char), len - ZERG_STAT_LEN, fp);
    printf("Name: ");
    for (int i = 0; i < len - ZERG_STAT_LEN; i++) {
        printf("%c", name[i]);
    }
    putchar('\n');

    free(name);
    return;
}

void z_cmd_parse(FILE *fp, ZergHeader_t *zh)
{
    int len = 0;
    ZergCmdPayload_t zcp;
    ZergCommand_t cmds[] = {
        {0, "GET_STATUS"}, {1, "GOTO"},
        {2, "GET_GPS"}, {3, "NONE"},
        {4, "RETURN"}, {5, "GET_GROUP"},
        {6, "STOP"}, {7, "REPEAT"},
    };

    len = NTOH3(zh->zh_len);
    len -= ZERG_SIZE;
#ifdef DEBUG
    printf("DEBUG: PAYLOAD IS %d\n", len);
#endif

    if (len == 2) {
        /* No parameters passed */
        fread(&zcp, len, 1, fp);
        printf("DEBUG: COMMAND IS %s\n", cmds[zcp.zcp_command].cmd); /* TODO: might need to ntohs zcp_command */
        printf("%s\n", cmds[zcp.zcp_command].cmd);
    }

    return;
}
