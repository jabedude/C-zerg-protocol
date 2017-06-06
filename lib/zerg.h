#ifndef ZERG_HEADER
#define ZERG_HEADER

#include "pcap.h"

/* Definitions */
#define ZERG_STAT_LEN 12

/* Structures */
typedef struct zerg_breed {
    int ind;
    const char *breed;
} ZergBreed_t;

typedef struct zerg_status_payload {
    uint8_t zsp_hp[3];
    uint8_t zsp_armor;
    uint8_t zsp_maxhp[3];
    uint8_t zsp_ztype;
    uint32_t zsp_speed;
} ZergStatPayload_t;

/* Macros */
/* 
This macro is a network to host endianness switcher for 3 byte values.
*/
#define NTOH3(x) ((int) x[0] << 16) | ((int) (x[1]) << 8) | ((int) (x[2]))

/* Function prototypes */
void z_msg_parse(FILE *fp, ZergHeader_t *zh);
void z_status_parse(FILE *fp, ZergHeader_t *zh);
void z_cmd_parse(FILE *fp);
void z_gps_parse(FILE *fp, ZergHeader_t *zh);

#endif
