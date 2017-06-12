#ifndef ZERG_HEADER
#define ZERG_HEADER

#include "pcap.h"

/* Definitions */
#define ZERG_STAT_LEN 12
#define ZERG_DST_PORT 3751
#define MAX_PACKET_CAPTURE 65536

/* Structures */
/* TODO: consider using same struct array for breeds and commands */
typedef struct zerg_breed {
    int ind;
    const char *breed;
} ZergBreed_t;

typedef struct zerg_command {
    int ind;
    const char *cmd;
} ZergCommand_t;

typedef struct zerg_status_payload {
    uint8_t zsp_hp[3];
    uint8_t zsp_armor;
    uint8_t zsp_maxhp[3];
    uint8_t zsp_ztype;
    uint32_t zsp_speed;
} ZergStatPayload_t;

typedef struct zerg_command_payload {
    uint16_t zcp_command;
    uint16_t zcp_param_one;
    uint32_t zcp_param_two;
} ZergCmdPayload_t;

typedef struct zerg_gps_payload {
    uint64_t zgp_long;
    uint64_t zgp_lat;
    uint32_t zgp_alt;
    uint32_t zgp_bearing;
    uint32_t zgp_speed;
    uint32_t zgp_acc;
} ZergGpsPayload_t;

/* Macros */
/*
This macro is a network to host endianness switcher for 3 byte values.
*/
#define NTOH3(x) ((int) x[0] << 16) | ((int) (x[1]) << 8) | ((int) (x[2]))
#define IEEE16(x) (x << 8 | x >> 8)
#define COMP2(x) (~x) + 1

/* Function prototypes */
double ieee_convert64(uint64_t num);
double ieee_convert32(uint32_t num);
uint64_t ntoh64(uint64_t val);
void z_msg_parse(FILE *fp, ZergHeader_t *zh);
void z_status_parse(FILE *fp, ZergHeader_t *zh);
void z_cmd_parse(FILE *fp, ZergHeader_t *zh);
void z_gps_parse(FILE *fp, ZergHeader_t *zh);
void write_stat(FILE *pfp, ZergHeader_t *zh, ZergStatPayload_t *zsp, char *name);
void write_cmd(FILE *pfp, ZergHeader_t *zh, ZergCmdPayload_t *zcp);

#endif
