#ifndef DETECTOR_H
#define DETECTOR_H

#include <stdint.h>
#include <stddef.h>
#include "parser.h"

/* --------------- Detection types --------------- */

typedef enum {
    DETECTION_PORT_SCAN  = 0,
    DETECTION_ARP_SPOOF  = 1,
    DETECTION_DNS_TUNNEL = 2
} detection_type_t;

/* --------------- Result struct --------------- */

typedef struct {
    detection_type_t type;
    double           first_seen;
    double           last_seen;
    uint32_t         src_ip;
    uint32_t         dst_ip;
    uint32_t         port_count;     /* PORT_SCAN: number of distinct ports */
    char             dns_query[256]; /* DNS_TUNNEL: suspicious label/name   */
    char             description[512];
} detection_result_t;

/* --------------- Configuration --------------- */

typedef struct {
    double   port_scan_window_sec;  /* time window for port scan detection  */
    uint32_t port_scan_threshold;   /* distinct ports to trigger alert      */
    uint32_t dns_label_max_len;     /* max DNS label length before alert    */
} detector_config_t;

/* Default configuration */
#define DETECTOR_CONFIG_DEFAULT { \
    .port_scan_window_sec = 10.0,  \
    .port_scan_threshold  = 15,    \
    .dns_label_max_len    = 40     \
}

/* --------------- API --------------- */

/**
 * Run all detectors on every packet from the capture.
 * Populates *results (dynamically allocated) with detections.
 * Returns the number of detections, or -1 on error.
 */
int detector_run(capture_t *cap,
                 const detector_config_t *config,
                 detection_result_t **results);

/**
 * Free the results array returned by detector_run.
 */
void detector_free(detection_result_t *results);

#endif /* DETECTOR_H */
