#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>

#include "parser.h"
#include "detector.h"
#include "reporter.h"

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [OPTIONS] <capture.pcap>\n"
            "\n"
            "Options:\n"
            "  -o <file>    Write JSON report to <file> (default: stdout)\n"
            "  -t <sec>     Port-scan time window in seconds (default: 10)\n"
            "  -p <count>   Port-scan threshold (default: 15)\n"
            "  -l <len>     DNS label max length before alert (default: 40)\n"
            "  -h           Show this help message\n"
            "\n"
            "Examples:\n"
            "  %s capture.pcap\n"
            "  %s -o report.json -t 5 -p 20 capture.pcap\n"
            "\n"
            "Output: JSON report consumed by threat-correlation-engine.\n",
            prog, prog, prog);
}

int main(int argc, char *argv[])
{
    const char *output_file   = NULL;
    double      time_window   = 10.0;
    uint32_t    port_thresh   = 15;
    uint32_t    dns_label_max = 40;

    int opt;
    while ((opt = getopt(argc, argv, "o:t:p:l:h")) != -1) {
        switch (opt) {
        case 'o': output_file   = optarg;            break;
        case 't': time_window   = atof(optarg);      break;
        case 'p': port_thresh   = (uint32_t)atoi(optarg); break;
        case 'l': dns_label_max = (uint32_t)atoi(optarg); break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: no pcap file specified.\n");
        usage(argv[0]);
        return 1;
    }

    const char *pcap_file = argv[optind];

    /* Open capture */
    char err_buf[PCAP_ERRBUF_SIZE];
    capture_t *cap = parser_open(pcap_file, err_buf);
    if (!cap) {
        fprintf(stderr, "Error opening '%s': %s\n", pcap_file, err_buf);
        return 1;
    }

    /* Configure detectors */
    detector_config_t cfg = {
        .port_scan_window_sec = time_window,
        .port_scan_threshold  = port_thresh,
        .dns_label_max_len    = dns_label_max
    };

    /* Run detection */
    detection_result_t *results = NULL;
    int count = detector_run(cap, &cfg, &results);
    parser_close(cap);

    if (count < 0) {
        fprintf(stderr, "Error: detection failed.\n");
        return 1;
    }

    /* Open output stream */
    FILE *out = stdout;
    if (output_file) {
        out = fopen(output_file, "w");
        if (!out) {
            perror(output_file);
            detector_free(results);
            return 1;
        }
    }

    /* Write JSON report */
    int rc = reporter_write_json(out, pcap_file, results, (size_t)count);
    if (rc != 0)
        fprintf(stderr, "Warning: error writing JSON report.\n");

    if (output_file) {
        fclose(out);
        fprintf(stderr, "Report written to '%s' (%d alert(s)).\n",
                output_file, count);
    } else {
        fprintf(stderr, "%d alert(s) detected.\n", count);
    }

    detector_free(results);
    return rc;
}
