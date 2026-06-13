#include "detector.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

/* ================================================================
 * Internal data structures
 * ================================================================ */

#define PORT_TRACK_BUCKETS 256
#define PORT_TRACK_MAX_PORTS 1024

typedef struct {
    uint32_t  src_ip;
    uint16_t  ports[PORT_TRACK_MAX_PORTS];
    uint32_t  port_count;
    double    first_seen;
    double    last_seen;
    int       active;
} port_track_entry_t;

typedef struct {
    uint8_t  mac[6];
    uint32_t ip;
    int      active;
} arp_mac_entry_t;

#define ARP_TRACK_BUCKETS 256

/* ================================================================
 * Utility
 * ================================================================ */

static void ip_to_str(uint32_t ip, char *buf, size_t len)
{
    snprintf(buf, len, "%u.%u.%u.%u",
             (ip >> 24) & 0xff,
             (ip >> 16) & 0xff,
             (ip >>  8) & 0xff,
             (ip      ) & 0xff);
}

/* Simple hash for uint32_t IP */
static uint32_t ip_hash(uint32_t ip)
{
    return (ip ^ (ip >> 16)) % PORT_TRACK_BUCKETS;
}

/* Simple hash for 6-byte MAC */
static uint32_t mac_hash(const uint8_t *mac)
{
    uint32_t h = 0;
    for (int i = 0; i < 6; i++)
        h = h * 31 + mac[i];
    return h % ARP_TRACK_BUCKETS;
}

/* ================================================================
 * Results accumulator
 * ================================================================ */

typedef struct {
    detection_result_t *data;
    size_t              count;
    size_t              capacity;
} result_list_t;

static int result_push(result_list_t *list, const detection_result_t *r)
{
    if (list->count >= list->capacity) {
        size_t new_cap = list->capacity ? list->capacity * 2 : 16;
        detection_result_t *tmp = realloc(list->data,
                                          new_cap * sizeof(detection_result_t));
        if (!tmp) return -1;
        list->data     = tmp;
        list->capacity = new_cap;
    }
    list->data[list->count++] = *r;
    return 0;
}

/* ================================================================
 * Port-scan detector
 * ================================================================ */

typedef struct {
    port_track_entry_t *buckets;   /* PORT_TRACK_BUCKETS entries */
    const detector_config_t *cfg;
    result_list_t *results;
} port_scan_ctx_t;

static void port_scan_ctx_init(port_scan_ctx_t *ctx,
                               const detector_config_t *cfg,
                               result_list_t *results)
{
    ctx->buckets = calloc(PORT_TRACK_BUCKETS, sizeof(port_track_entry_t));
    ctx->cfg     = cfg;
    ctx->results = results;
}

static void port_scan_ctx_free(port_scan_ctx_t *ctx)
{
    free(ctx->buckets);
}

static int port_already_seen(port_track_entry_t *entry, uint16_t port)
{
    for (uint32_t i = 0; i < entry->port_count; i++)
        if (entry->ports[i] == port) return 1;
    return 0;
}

static void port_scan_process(port_scan_ctx_t *ctx, const packet_t *pkt)
{
    /* Only track SYN packets (flag bit 0x02 set, no ACK 0x10) */
    if (pkt->protocol != PROTO_TCP) return;
    if (!(pkt->tcp_flags & 0x02)) return;
    if (  pkt->tcp_flags & 0x10)  return;  /* ignore SYN-ACK */

    uint32_t idx = ip_hash(pkt->src_ip);
    port_track_entry_t *entry = &ctx->buckets[idx];

    /* Handle collision: evict if different source IP */
    if (entry->active && entry->src_ip != pkt->src_ip) {
        memset(entry, 0, sizeof(*entry));
    }

    if (!entry->active) {
        entry->src_ip     = pkt->src_ip;
        entry->first_seen = pkt->timestamp;
        entry->last_seen  = pkt->timestamp;
        entry->port_count = 0;
        entry->active     = 1;
    }

    /* Reset window if packet is outside the time window */
    if (pkt->timestamp - entry->first_seen > ctx->cfg->port_scan_window_sec) {
        entry->first_seen = pkt->timestamp;
        entry->port_count = 0;
    }

    entry->last_seen = pkt->timestamp;

    if (!port_already_seen(entry, pkt->dst_port)) {
        if (entry->port_count < PORT_TRACK_MAX_PORTS)
            entry->ports[entry->port_count++] = pkt->dst_port;
    }

    if (entry->port_count >= ctx->cfg->port_scan_threshold) {
        detection_result_t r;
        memset(&r, 0, sizeof(r));
        r.type       = DETECTION_PORT_SCAN;
        r.first_seen = entry->first_seen;
        r.last_seen  = entry->last_seen;
        r.src_ip     = entry->src_ip;
        r.dst_ip     = pkt->dst_ip;
        r.port_count = entry->port_count;

        char src_buf[16], dst_buf[16];
        ip_to_str(r.src_ip, src_buf, sizeof(src_buf));
        ip_to_str(r.dst_ip, dst_buf, sizeof(dst_buf));
        snprintf(r.description, sizeof(r.description),
                 "SYN scan detected: %u distinct ports in %.2fs from %s to %s",
                 r.port_count,
                 r.last_seen - r.first_seen,
                 src_buf, dst_buf);

        result_push(ctx->results, &r);
        /* Reset to avoid duplicate alerts for the same burst */
        memset(entry, 0, sizeof(*entry));
    }
}

/* ================================================================
 * ARP-spoof detector
 * ================================================================ */

typedef struct {
    arp_mac_entry_t *buckets;  /* ARP_TRACK_BUCKETS entries */
    result_list_t   *results;
} arp_spoof_ctx_t;

static void arp_spoof_ctx_init(arp_spoof_ctx_t *ctx, result_list_t *results)
{
    ctx->buckets = calloc(ARP_TRACK_BUCKETS, sizeof(arp_mac_entry_t));
    ctx->results = results;
}

static void arp_spoof_ctx_free(arp_spoof_ctx_t *ctx)
{
    free(ctx->buckets);
}

static void arp_spoof_process(arp_spoof_ctx_t *ctx, const packet_t *pkt)
{
    if (pkt->ethertype != ETHERTYPE_ARP) return;
    if (pkt->arp_oper != 1 && pkt->arp_oper != 2) return;  /* only request/reply */

    uint32_t idx = mac_hash(pkt->arp_sha);
    arp_mac_entry_t *entry = &ctx->buckets[idx];

    if (!entry->active) {
        memcpy(entry->mac, pkt->arp_sha, 6);
        entry->ip     = pkt->arp_spa;
        entry->active = 1;
        return;
    }

    /* Collision: different MAC in same bucket */
    if (memcmp(entry->mac, pkt->arp_sha, 6) != 0) {
        /* Overwrite with new entry - simple eviction */
        memcpy(entry->mac, pkt->arp_sha, 6);
        entry->ip = pkt->arp_spa;
        return;
    }

    /* Same MAC announcing a different IP */
    if (entry->ip != pkt->arp_spa && pkt->arp_spa != 0) {
        detection_result_t r;
        memset(&r, 0, sizeof(r));
        r.type       = DETECTION_ARP_SPOOF;
        r.first_seen = pkt->timestamp;
        r.last_seen  = pkt->timestamp;
        r.src_ip     = pkt->arp_spa;
        r.dst_ip     = pkt->arp_tpa;

        char old_ip[16], new_ip[16];
        ip_to_str(entry->ip,    old_ip, sizeof(old_ip));
        ip_to_str(pkt->arp_spa, new_ip, sizeof(new_ip));
        snprintf(r.description, sizeof(r.description),
                 "ARP spoofing detected: MAC %02x:%02x:%02x:%02x:%02x:%02x "
                 "previously announced %s, now announces %s",
                 pkt->arp_sha[0], pkt->arp_sha[1], pkt->arp_sha[2],
                 pkt->arp_sha[3], pkt->arp_sha[4], pkt->arp_sha[5],
                 old_ip, new_ip);

        result_push(ctx->results, &r);
        /* Update entry to avoid repeated alerts */
        entry->ip = pkt->arp_spa;
    }
}

/* ================================================================
 * DNS-tunnel detector
 * ================================================================ */

typedef struct {
    const detector_config_t *cfg;
    result_list_t           *results;
} dns_tunnel_ctx_t;

/*
 * Minimal DNS header (first 12 bytes of UDP payload).
 */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_hdr_t;

static void dns_tunnel_process(dns_tunnel_ctx_t *ctx, const packet_t *pkt)
{
    /* DNS: UDP port 53 */
    if (pkt->protocol != PROTO_UDP) return;
    if (pkt->dst_port != 53 && pkt->src_port != 53) return;
    if (!pkt->payload || pkt->payload_len < sizeof(dns_hdr_t)) return;

    const uint8_t *p   = pkt->payload + sizeof(dns_hdr_t);
    size_t         rem = pkt->payload_len - sizeof(dns_hdr_t);

    /* Parse QNAME labels */
    char full_name[256] = {0};
    size_t name_off = 0;

    while (rem > 0) {
        uint8_t label_len = *p;
        p++;   rem--;

        if (label_len == 0) break;  /* root label */

        /* Pointer (compression) - skip */
        if ((label_len & 0xc0) == 0xc0) {
            if (rem >= 1) { p++; rem--; }
            break;
        }

        if (label_len > rem) break;

        /* Check label length against threshold */
        if (label_len > ctx->cfg->dns_label_max_len) {
            detection_result_t r;
            memset(&r, 0, sizeof(r));
            r.type       = DETECTION_DNS_TUNNEL;
            r.first_seen = pkt->timestamp;
            r.last_seen  = pkt->timestamp;
            r.src_ip     = pkt->src_ip;
            r.dst_ip     = pkt->dst_ip;

            /* Copy label into dns_query */
            size_t copy_len = label_len < 255 ? label_len : 255;
            memcpy(r.dns_query, p, copy_len);
            r.dns_query[copy_len] = '\0';

            snprintf(r.description, sizeof(r.description),
                     "DNS tunneling suspected: label length %u exceeds threshold %u"
                     " in query for domain '%.*s...'",
                     label_len, ctx->cfg->dns_label_max_len,
                     (int)(copy_len > 30 ? 30 : copy_len), r.dns_query);

            result_push(ctx->results, &r);
            return;  /* one alert per packet */
        }

        /* Append label to full_name for context */
        if (name_off + label_len + 1 < sizeof(full_name)) {
            memcpy(full_name + name_off, p, label_len);
            name_off += label_len;
            full_name[name_off++] = '.';
        }

        p   += label_len;
        rem -= label_len;
    }
}

/* ================================================================
 * Public API
 * ================================================================ */

int detector_run(capture_t *cap,
                 const detector_config_t *config,
                 detection_result_t **results)
{
    result_list_t list = {NULL, 0, 0};

    port_scan_ctx_t  ps_ctx;
    arp_spoof_ctx_t  arp_ctx;
    dns_tunnel_ctx_t dns_ctx;

    port_scan_ctx_init(&ps_ctx,  config, &list);
    arp_spoof_ctx_init(&arp_ctx, &list);
    dns_ctx.cfg     = config;
    dns_ctx.results = &list;

    packet_t pkt;
    int rc;

    while ((rc = parser_next(cap, &pkt)) == 1) {
        port_scan_process(&ps_ctx,  &pkt);
        arp_spoof_process(&arp_ctx, &pkt);
        dns_tunnel_process(&dns_ctx, &pkt);
    }

    port_scan_ctx_free(&ps_ctx);
    arp_spoof_ctx_free(&arp_ctx);

    if (rc == -1) {
        free(list.data);
        return -1;
    }

    *results = list.data;
    return (int)list.count;
}

void detector_free(detection_result_t *results)
{
    free(results);
}
