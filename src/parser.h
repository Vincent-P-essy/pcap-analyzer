#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <stddef.h>

/* --------------- Network header structs (packed) --------------- */

#pragma pack(push, 1)

typedef struct {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
} eth_header_t;

typedef struct {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
} ip_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} tcp_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

typedef struct {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t oper;
    uint8_t  sha[6];  /* sender hardware address */
    uint32_t spa;     /* sender protocol address */
    uint8_t  tha[6];  /* target hardware address */
    uint32_t tpa;     /* target protocol address */
} arp_header_t;

#pragma pack(pop)

/* --------------- Parsed packet representation --------------- */

#define ETHERTYPE_IP  0x0800
#define ETHERTYPE_ARP 0x0806

#define PROTO_TCP 6
#define PROTO_UDP 17

typedef struct {
    double   timestamp;      /* seconds since epoch (with sub-second) */
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  tcp_flags;
    uint8_t  src_mac[6];
    uint16_t ethertype;
    uint8_t  protocol;       /* IP protocol (TCP/UDP) or 0 for ARP */
    /* ARP fields (valid when ethertype == ETHERTYPE_ARP) */
    uint8_t  arp_sha[6];
    uint32_t arp_spa;
    uint32_t arp_tpa;
    uint16_t arp_oper;
    /* Payload */
    const uint8_t *payload;
    size_t         payload_len;
} packet_t;

/* Opaque capture handle */
typedef struct capture_s capture_t;

/* --------------- API --------------- */

/**
 * Open a pcap file for reading.
 * Returns a capture_t* on success, NULL on error.
 * err_buf must be at least PCAP_ERRBUF_SIZE bytes.
 */
capture_t *parser_open(const char *filename, char *err_buf);

/**
 * Read the next packet from the capture.
 * Returns  1 if a packet was successfully read into *pkt.
 * Returns -2 on EOF.
 * Returns -1 on error.
 */
int parser_next(capture_t *cap, packet_t *pkt);

/**
 * Close the capture and free resources.
 */
void parser_close(capture_t *cap);

#endif /* PARSER_H */
