#ifndef CODEC_PCAP_HEADER
#define CODEC_PCAP_HEADER

#include <sys/types.h>
#include <netinet/in.h>
#include <stdint.h>

/* Defines */
#define ETH_SIZE 14
#define UDP_SIZE 0xC

/* Structs for reading a pcap file */

typedef struct pcap_header {
    uint32_t magic_num;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} PcapHeader_t;


typedef struct pcap_pack_header {
    uint32_t epoch;
    uint32_t ms_from_epoch;
    uint32_t recorded_len;
    uint32_t orig_len;
} PcapPackHeader_t;

typedef struct eth_header {
    u_char eth_dhost[6];
    u_char eth_shost[6];
    u_short eth_type;
} EthHeader_t;

typedef struct ip_header {
    u_char  ip_vhl;
    u_char  ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
    u_char  ip_ttl;
    u_char  ip_p;
    u_short ip_sum;
    struct  in_addr ip_src,ip_dst;
} IpHeader_t;

typedef struct udp_header {
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_ulen;
    u_short uh_sum;
} UdpHeader_t;

typedef struct zerg_header {
    uint8_t zh_vt;
    uint32_t zh_len : 24;
    u_short zh_dest;
    u_short zh_src;
    uint32_t zg_seqid;
} ZergHeader_t;

#endif
