#ifndef ZERG_HEADER
#define ZERG_HEADER

#include "pcap.h"

/* Macros */
/* 
This macro is a network to host endianness switcher for 3 byte values.
*/
#define NTOH3(x) ((int) x[0] << 16) | ((int) (x[1]) << 8) | ((int) (x[2]))

/* Function prototypes */
void z_msg_parse(FILE *fp, ZergHeader_t *zh);
void z_status_parse(FILE *fp);
void z_cmd_parse(FILE *fp);
void z_gps_parse(FILE *fp, ZergHeader_t *zh);

#endif
