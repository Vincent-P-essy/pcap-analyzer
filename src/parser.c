#include "parser.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

struct capture_s {
    pcap_t *handle;
};

capture_t *parser_open(const char *filename, char *err_buf)
{
    pcap_t *handle = pcap_open_offline(filename, err_buf);
    if (!handle)
        return NULL;

    capture_t *cap = malloc(sizeof(capture_t));
    if (!cap) {
        pcap_close(handle);
        return NULL;
    }
    cap->handle = handle;
    return cap;
}

int parser_next(capture_t *cap, packet_t *pkt)
{
    struct pcap_pkthdr *header;
    const uint8_t *data;

    int rc = pcap_next_ex(cap->handle, &header, &data);
    if (rc == PCAP_ERROR_BREAK || rc == 0)  /* EOF or no more packets */
        return -2;
    if (rc < 0)
        return -1;

    memset(pkt, 0, sizeof(*pkt));
    pkt->timestamp = (double)header->ts.tv_sec
                   + (double)header->ts.tv_usec / 1e6;

    if (header->caplen < sizeof(eth_header_t))
        return parser_next(cap, pkt);  /* skip malformed */

    const eth_header_t *eth = (const eth_header_t *)data;
    pkt->ethertype = ntohs(eth->ethertype);
    memcpy(pkt->src_mac, eth->src, 6);

    const uint8_t *next = data + sizeof(eth_header_t);
    size_t remaining    = header->caplen - sizeof(eth_header_t);

    if (pkt->ethertype == ETHERTYPE_ARP) {
        if (remaining < sizeof(arp_header_t))
            return parser_next(cap, pkt);
        const arp_header_t *arp = (const arp_header_t *)next;
        pkt->arp_oper = ntohs(arp->oper);
        memcpy(pkt->arp_sha, arp->sha, 6);
        pkt->arp_spa = ntohl(arp->spa);
        pkt->arp_tpa = ntohl(arp->tpa);
        pkt->protocol = 0;
        return 1;
    }

    if (pkt->ethertype != ETHERTYPE_IP)
        return parser_next(cap, pkt);  /* skip non-IP/ARP */

    if (remaining < sizeof(ip_header_t))
        return parser_next(cap, pkt);

    const ip_header_t *ip = (const ip_header_t *)next;
    uint8_t ihl = (ip->version_ihl & 0x0f) * 4;
    if (remaining < ihl)
        return parser_next(cap, pkt);

    pkt->src_ip   = ntohl(ip->src);
    pkt->dst_ip   = ntohl(ip->dst);
    pkt->protocol = ip->protocol;

    next      += ihl;
    remaining -= ihl;

    if (ip->protocol == PROTO_TCP) {
        if (remaining < sizeof(tcp_header_t))
            return parser_next(cap, pkt);
        const tcp_header_t *tcp = (const tcp_header_t *)next;
        pkt->src_port  = ntohs(tcp->src_port);
        pkt->dst_port  = ntohs(tcp->dst_port);
        pkt->tcp_flags = tcp->flags;
        uint8_t tcp_hdr_len = ((tcp->data_offset >> 4) & 0x0f) * 4;
        if (remaining >= tcp_hdr_len) {
            pkt->payload     = next + tcp_hdr_len;
            pkt->payload_len = remaining - tcp_hdr_len;
        }
    } else if (ip->protocol == PROTO_UDP) {
        if (remaining < sizeof(udp_header_t))
            return parser_next(cap, pkt);
        const udp_header_t *udp = (const udp_header_t *)next;
        pkt->src_port    = ntohs(udp->src_port);
        pkt->dst_port    = ntohs(udp->dst_port);
        pkt->payload     = next + sizeof(udp_header_t);
        pkt->payload_len = (remaining > sizeof(udp_header_t))
                         ? remaining - sizeof(udp_header_t) : 0;
    }

    return 1;
}

void parser_close(capture_t *cap)
{
    if (!cap) return;
    pcap_close(cap->handle);
    free(cap);
}
