#include <stdio.h>

#include "zerg.h"
#include "pcap.h"

void z_msg_parse(FILE *fp, ZergHeader_t *zh)
{
    printf("DEBUG: TOTAL LEN IS %x\n", zh->zh_len);
    return;
}
