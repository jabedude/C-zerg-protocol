#include <stdio.h>
#include <stdlib.h>

#include "zerg.h"
#include "pcap.h"

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
