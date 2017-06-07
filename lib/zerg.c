#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "zerg.h"
#include "pcap.h"

double
convert64ToDouble(uint64_t num)
{

    uint8_t sign;

    uint16_t exponent;

    uint64_t mantisa;

    double result = 0;



    sign = num >> 63;

    exponent = (num >> 52 & 0x7FF) - 1023;

    mantisa = num & 0xFFFFFFFFFFFFF;

    result = (mantisa *pow(2, -52)) + 1;

    result *= pow(1, sign) * pow(2, exponent);

    return result;

}

double ieee_convert32(uint32_t num)
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
    printf("Speed: %fm/s\n", ieee_convert32(ntohl(zsp.zsp_speed))); /* TODO: Drop trailing zeros. try sprintf() */
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
    printf("DEBUG: PAYLOAD IS %d\n", len);

    /* TODO: try moving all reads outside of if..else */
    if (len == 2) {
        /* No parameters passed */
        fread(&zcp, len, 1, fp);
        printf("DEBUG: COMMAND IS %s\n", cmds[ntohs(zcp.zcp_command)].cmd); /* TODO: might need to ntohs zcp_command */
        printf("%s\n", cmds[zcp.zcp_command].cmd);
    } else {
        /* These commands have parameters */
        fread(&zcp, len, 1, fp);
        printf("DEBUG: COMMAND IS %s\n", cmds[ntohs(zcp.zcp_command)].cmd); /* TODO: might need to ntohs zcp_command */
        printf("%s\n", cmds[ntohs(zcp.zcp_command)].cmd);

        switch (ntohs(zcp.zcp_command)) {
            case 1 :
#ifdef DEBUG
                printf("DEBUG: PARAM 1 IS: %d\n", ntohs(zcp.zcp_param_one));
                printf("DEBUG: PARAM 2 IS: %d\n", ntohs(zcp.zcp_param_two));
#endif
                /* TODO: check direction and distance. Might need to convert to precision */
                printf("Move %d m at bearing %f.\n", ntohs(zcp.zcp_param_one), ieee_convert32(ntohl(zcp.zcp_param_two)));
                break;
            case 3 :
                break;
            case 5 :
#ifdef DEBUG
                printf("DEBUG: PARAM 1 IS: %d\n", ntohs(zcp.zcp_param_one));
                printf("DEBUG: PARAM 2 IS: %d\n", ntohs(zcp.zcp_param_two));
#endif
                if (ntohs(zcp.zcp_param_one))
                    printf("ADD to ");
                else
                    printf("Remove from ");
                printf("group ID %d\n", COMP2((int32_t) zcp.zcp_param_two));
                break;
            case 7 :
                break;
        }
    }

    return;
}
