#ifndef ZERG_HEADER
#define ZERG_HEADER

#include "pcap.h"

/* Function prototypes */
void z_msg_parse(FILE *fp, ZergHeader_t *zh);
void z_status_parse(FILE *fp);
void z_cmd_parse(FILE *fp);
void z_gps_parse(FILE *fp, ZergHeader_t *zh);

#endif
