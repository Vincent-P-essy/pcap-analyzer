/*
 * test_detector.c - Minimal unit tests for pcap-analyzer detectors.
 *
 * Tests craft packet_t structs directly and exercise internal logic
 * by calling detector_run() on synthetic data via a fake capture.
 *
 * Build: see Makefile `test` target.
 * Run:   ./obj/test_detector
 * Exit:  0 if all tests pass, non-zero otherwise.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "parser.h"
#include "detector.h"
#include "reporter.h"

/* ================================================================
 * Fake capture implementation
 * The real capture_t is opaque; we provide our own for testing.
 * ================================================================ */

struct capture_s {
    packet_t *packets;
    size_t    count;
    size_t    pos;
};

/* Implement parser_next for tests */
int parser_next(capture_t *cap, packet_t *pkt)
{
    if (cap->pos >= cap->count)
        return -2;  /* EOF */
    *pkt = cap->packets[cap->pos++];
    return 1;
}

void parser_close(capture_t *cap) { (void)cap; }

capture_t *parser_open(const char *filename, char *err_buf)
{
    (void)filename; (void)err_buf;
    return NULL;  /* not used in tests */
}

/* Helper: create a fake capture from a packet array */
static capture_t *make_capture(packet_t *pkts, size_t n)
{
    capture_t *c = malloc(sizeof(*c));
    assert(c);
    c->packets = pkts;
    c->count   = n;
    c->pos     = 0;
    return c;
}

/* ================================================================
 * Test helpers
 * ================================================================ */

static int tests_run    = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond, msg) do { \
    tests_run++; \
    if (cond) { \
        tests_passed++; \
        printf("  [PASS] %s\n", msg); \
    } else { \
        printf("  [FAIL] %s  (line %d)\n", msg, __LINE__); \
    } \
} while (0)

/* ================================================================
 * Test: port scan detection
 * ================================================================ */

static void test_port_scan_detected(void)
{
    printf("\n[TEST] Port-scan detection\n");

    const int N = 20;
    packet_t pkts[N];
    memset(pkts, 0, sizeof(pkts));

    for (int i = 0; i < N; i++) {
        pkts[i].ethertype  = ETHERTYPE_IP;
        pkts[i].protocol   = PROTO_TCP;
        pkts[i].tcp_flags  = 0x02;           /* SYN */
        pkts[i].src_ip     = 0xc0a80164;     /* 192.168.1.100 */
        pkts[i].dst_ip     = 0x0a000001;     /* 10.0.0.1 */
        pkts[i].dst_port   = (uint16_t)(1000 + i);
        pkts[i].timestamp  = 1700000000.0 + i * 0.1;
    }

    detector_config_t cfg = {
        .port_scan_window_sec = 30.0,
        .port_scan_threshold  = 15,
        .dns_label_max_len    = 40
    };

    detection_result_t *results = NULL;
    capture_t *cap = make_capture(pkts, N);
    int count = detector_run(cap, &cfg, &results);
    free(cap);

    TEST_ASSERT(count >= 1, "At least one port-scan alert produced");
    if (count >= 1) {
        TEST_ASSERT(results[0].type == DETECTION_PORT_SCAN,
                    "Alert type is PORT_SCAN");
        TEST_ASSERT(results[0].src_ip == 0xc0a80164,
                    "Source IP matches attacker");
        TEST_ASSERT(results[0].port_count >= 15,
                    "Port count >= threshold");
    }

    detector_free(results);
}

static void test_port_scan_not_triggered_below_threshold(void)
{
    printf("\n[TEST] Port-scan NOT triggered below threshold\n");

    const int N = 10;
    packet_t pkts[N];
    memset(pkts, 0, sizeof(pkts));

    for (int i = 0; i < N; i++) {
        pkts[i].ethertype = ETHERTYPE_IP;
        pkts[i].protocol  = PROTO_TCP;
        pkts[i].tcp_flags = 0x02;
        pkts[i].src_ip    = 0xc0a80165;
        pkts[i].dst_port  = (uint16_t)(2000 + i);
        pkts[i].timestamp = 1700000000.0 + i * 0.1;
    }

    detector_config_t cfg = {
        .port_scan_window_sec = 30.0,
        .port_scan_threshold  = 15,
        .dns_label_max_len    = 40
    };

    detection_result_t *results = NULL;
    capture_t *cap = make_capture(pkts, N);
    int count = detector_run(cap, &cfg, &results);
    free(cap);

    TEST_ASSERT(count == 0, "No alert when below threshold");
    detector_free(results);
}

/* ================================================================
 * Test: ARP spoof detection
 * ================================================================ */

static void test_arp_spoof_detected(void)
{
    printf("\n[TEST] ARP-spoof detection\n");

    packet_t pkts[2];
    memset(pkts, 0, sizeof(pkts));

    /* Same MAC, first announces IP 192.168.1.1 */
    pkts[0].ethertype   = ETHERTYPE_ARP;
    pkts[0].arp_oper    = 2;  /* ARP reply */
    pkts[0].arp_sha[0]  = 0xde; pkts[0].arp_sha[1] = 0xad;
    pkts[0].arp_sha[2]  = 0xbe; pkts[0].arp_sha[3] = 0xef;
    pkts[0].arp_sha[4]  = 0x00; pkts[0].arp_sha[5] = 0x01;
    pkts[0].arp_spa     = 0xc0a80101;  /* 192.168.1.1 */
    pkts[0].arp_tpa     = 0xc0a80102;
    pkts[0].timestamp   = 1700000000.0;

    /* Same MAC, now announces IP 192.168.1.254 */
    pkts[1]             = pkts[0];
    pkts[1].arp_spa     = 0xc0a800fe;  /* 192.168.1.254 */
    pkts[1].timestamp   = 1700000001.0;

    detector_config_t cfg = {
        .port_scan_window_sec = 10.0,
        .port_scan_threshold  = 15,
        .dns_label_max_len    = 40
    };

    detection_result_t *results = NULL;
    capture_t *cap = make_capture(pkts, 2);
    int count = detector_run(cap, &cfg, &results);
    free(cap);

    TEST_ASSERT(count >= 1, "At least one ARP-spoof alert produced");
    if (count >= 1) {
        TEST_ASSERT(results[0].type == DETECTION_ARP_SPOOF,
                    "Alert type is ARP_SPOOF");
        TEST_ASSERT(results[0].src_ip == 0xc0a800fe,
                    "Source IP is the spoofed IP");
    }

    detector_free(results);
}

static void test_arp_no_alert_same_ip(void)
{
    printf("\n[TEST] No ARP alert when same MAC announces same IP\n");

    packet_t pkts[2];
    memset(pkts, 0, sizeof(pkts));

    for (int i = 0; i < 2; i++) {
        pkts[i].ethertype   = ETHERTYPE_ARP;
        pkts[i].arp_oper    = 1;
        pkts[i].arp_sha[0]  = 0xaa;
        pkts[i].arp_spa     = 0xc0a80101;
        pkts[i].timestamp   = 1700000000.0 + i;
    }

    detector_config_t cfg = {
        .port_scan_window_sec = 10.0,
        .port_scan_threshold  = 15,
        .dns_label_max_len    = 40
    };

    detection_result_t *results = NULL;
    capture_t *cap = make_capture(pkts, 2);
    int count = detector_run(cap, &cfg, &results);
    free(cap);

    TEST_ASSERT(count == 0, "No alert when same MAC keeps same IP");
    detector_free(results);
}

/* ================================================================
 * Test: DNS tunnel detection
 * ================================================================ */

static void test_dns_tunnel_detected(void)
{
    printf("\n[TEST] DNS-tunnel detection\n");

    /*
     * Build a minimal DNS query packet payload.
     * Structure: [DNS header 12B] [QNAME labels] [QTYPE 2B] [QCLASS 2B]
     *
     * DNS header (all zeros except qdcount=1):
     *   id=0x1234, flags=0x0100 (standard query), qdcount=1
     *
     * Label: 50-char label (exceeds default threshold of 40)
     */
    static const char long_label[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; /* 51 chars */

    uint8_t payload[256];
    memset(payload, 0, sizeof(payload));

    /* DNS header */
    payload[0] = 0x12; payload[1] = 0x34;  /* id */
    payload[2] = 0x01; payload[3] = 0x00;  /* flags: standard query */
    payload[4] = 0x00; payload[5] = 0x01;  /* qdcount = 1 */
    /* ancount, nscount, arcount = 0 */

    /* QNAME: one long label */
    size_t off = 12;
    uint8_t llen = (uint8_t)(sizeof(long_label) - 1);  /* exclude NUL */
    payload[off++] = llen;
    memcpy(payload + off, long_label, llen);
    off += llen;
    payload[off++] = 0;     /* root label */
    payload[off++] = 0x00; payload[off++] = 0x01;  /* QTYPE A */
    payload[off++] = 0x00; payload[off++] = 0x01;  /* QCLASS IN */

    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.ethertype   = ETHERTYPE_IP;
    pkt.protocol    = PROTO_UDP;
    pkt.src_ip      = 0xc0a80101;
    pkt.dst_ip      = 0x08080808;  /* 8.8.8.8 */
    pkt.dst_port    = 53;
    pkt.payload     = payload;
    pkt.payload_len = off;
    pkt.timestamp   = 1700000000.0;

    detector_config_t cfg = {
        .port_scan_window_sec = 10.0,
        .port_scan_threshold  = 15,
        .dns_label_max_len    = 40
    };

    detection_result_t *results = NULL;
    capture_t *cap = make_capture(&pkt, 1);
    int count = detector_run(cap, &cfg, &results);
    free(cap);

    TEST_ASSERT(count >= 1, "At least one DNS-tunnel alert produced");
    if (count >= 1) {
        TEST_ASSERT(results[0].type == DETECTION_DNS_TUNNEL,
                    "Alert type is DNS_TUNNEL");
        TEST_ASSERT(results[0].dst_ip == 0x08080808,
                    "Destination IP is the DNS server");
    }

    detector_free(results);
}

static void test_dns_no_alert_short_label(void)
{
    printf("\n[TEST] No DNS alert for short labels\n");

    /* Label: 10 chars - well below threshold */
    uint8_t payload[64];
    memset(payload, 0, sizeof(payload));

    payload[0] = 0x00; payload[1] = 0x01;
    payload[2] = 0x01; payload[3] = 0x00;
    payload[4] = 0x00; payload[5] = 0x01;

    size_t off = 12;
    payload[off++] = 10;
    memcpy(payload + off, "example123", 10);
    off += 10;
    payload[off++] = 3;
    memcpy(payload + off, "com", 3);
    off += 3;
    payload[off++] = 0;
    payload[off++] = 0x00; payload[off++] = 0x01;
    payload[off++] = 0x00; payload[off++] = 0x01;

    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.ethertype   = ETHERTYPE_IP;
    pkt.protocol    = PROTO_UDP;
    pkt.dst_port    = 53;
    pkt.payload     = payload;
    pkt.payload_len = off;
    pkt.timestamp   = 1700000000.0;

    detector_config_t cfg = {
        .port_scan_window_sec = 10.0,
        .port_scan_threshold  = 15,
        .dns_label_max_len    = 40
    };

    detection_result_t *results = NULL;
    capture_t *cap = make_capture(&pkt, 1);
    int count = detector_run(cap, &cfg, &results);
    free(cap);

    TEST_ASSERT(count == 0, "No alert for short DNS labels");
    detector_free(results);
}

/* ================================================================
 * Test: reporter JSON output
 * ================================================================ */

static void test_reporter_empty(void)
{
    printf("\n[TEST] Reporter produces valid JSON with 0 alerts\n");

    FILE *f = tmpfile();
    assert(f);

    int rc = reporter_write_json(f, "test.pcap", NULL, 0);
    TEST_ASSERT(rc == 0, "reporter_write_json returns 0 on success");

    rewind(f);
    char buf[512];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);

    TEST_ASSERT(strstr(buf, "\"alert_count\": 0") != NULL,
                "JSON contains alert_count 0");
    TEST_ASSERT(strstr(buf, "\"source_file\"") != NULL,
                "JSON contains source_file key");
    TEST_ASSERT(strstr(buf, "\"generated_at\"") != NULL,
                "JSON contains generated_at key");
}

static void test_reporter_with_alert(void)
{
    printf("\n[TEST] Reporter produces valid JSON with 1 alert\n");

    detection_result_t r;
    memset(&r, 0, sizeof(r));
    r.type       = DETECTION_PORT_SCAN;
    r.first_seen = 1700000000.0;
    r.last_seen  = 1700000005.0;
    r.src_ip     = 0xc0a80164;  /* 192.168.1.100 */
    r.dst_ip     = 0x0a000001;  /* 10.0.0.1 */
    r.port_count = 23;
    snprintf(r.description, sizeof(r.description),
             "SYN scan detected: 23 distinct ports in 5.00s");

    FILE *f = tmpfile();
    assert(f);

    int rc = reporter_write_json(f, "scan.pcap", &r, 1);
    TEST_ASSERT(rc == 0, "reporter_write_json returns 0");

    rewind(f);
    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);

    TEST_ASSERT(strstr(buf, "\"type\": \"PORT_SCAN\"") != NULL,
                "JSON contains PORT_SCAN type");
    TEST_ASSERT(strstr(buf, "\"severity\": \"HIGH\"") != NULL,
                "JSON contains HIGH severity");
    TEST_ASSERT(strstr(buf, "192.168.1.100") != NULL,
                "JSON contains src IP in dotted notation");
    TEST_ASSERT(strstr(buf, "10.0.0.1") != NULL,
                "JSON contains dst IP in dotted notation");
    TEST_ASSERT(strstr(buf, "\"alert_count\": 1") != NULL,
                "JSON contains alert_count 1");
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void)
{
    printf("=== pcap-analyzer unit tests ===\n");

    test_port_scan_detected();
    test_port_scan_not_triggered_below_threshold();
    test_arp_spoof_detected();
    test_arp_no_alert_same_ip();
    test_dns_tunnel_detected();
    test_dns_no_alert_short_label();
    test_reporter_empty();
    test_reporter_with_alert();

    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
