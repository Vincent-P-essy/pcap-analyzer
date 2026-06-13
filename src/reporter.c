#include "reporter.h"

#include <time.h>
#include <stdio.h>
#include <string.h>

/* Map detection_type_t to string */
static const char *type_to_str(detection_type_t t)
{
    switch (t) {
    case DETECTION_PORT_SCAN:  return "PORT_SCAN";
    case DETECTION_ARP_SPOOF:  return "ARP_SPOOF";
    case DETECTION_DNS_TUNNEL: return "DNS_TUNNEL";
    default:                   return "UNKNOWN";
    }
}

/* Map detection_type_t to severity */
static const char *type_to_severity(detection_type_t t)
{
    switch (t) {
    case DETECTION_PORT_SCAN:  return "HIGH";
    case DETECTION_ARP_SPOOF:  return "CRITICAL";
    case DETECTION_DNS_TUNNEL: return "MEDIUM";
    default:                   return "INFO";
    }
}

static void ip_to_str(uint32_t ip, char *buf, size_t len)
{
    snprintf(buf, len, "%u.%u.%u.%u",
             (ip >> 24) & 0xff,
             (ip >> 16) & 0xff,
             (ip >>  8) & 0xff,
             (ip      ) & 0xff);
}

/* Escape a string for JSON (handles backslash and double-quote) */
static void json_escape(FILE *out, const char *s)
{
    for (; *s; s++) {
        switch (*s) {
        case '"':  fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\n': fputs("\\n",  out); break;
        case '\r': fputs("\\r",  out); break;
        case '\t': fputs("\\t",  out); break;
        default:   fputc(*s, out);     break;
        }
    }
}

int reporter_write_json(FILE *out,
                        const char *filename,
                        const detection_result_t *results,
                        size_t count)
{
    /* Generate ISO-8601 timestamp */
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", tm_info);

    if (fprintf(out, "{\n") < 0) return -1;
    fprintf(out, "  \"source_file\": \"");
    json_escape(out, filename);
    fprintf(out, "\",\n");
    fprintf(out, "  \"generated_at\": \"%s\",\n", ts);
    fprintf(out, "  \"alert_count\": %zu,\n", count);
    fprintf(out, "  \"alerts\": [");

    for (size_t i = 0; i < count; i++) {
        const detection_result_t *r = &results[i];
        char src_buf[16], dst_buf[16];
        ip_to_str(r->src_ip, src_buf, sizeof(src_buf));
        ip_to_str(r->dst_ip, dst_buf, sizeof(dst_buf));

        fprintf(out, "%s\n    {\n", i == 0 ? "" : ",");
        fprintf(out, "      \"type\": \"%s\",\n",     type_to_str(r->type));
        fprintf(out, "      \"severity\": \"%s\",\n", type_to_severity(r->type));
        fprintf(out, "      \"src_ip\": \"%s\",\n",  src_buf);
        fprintf(out, "      \"dst_ip\": \"%s\",\n",  dst_buf);
        fprintf(out, "      \"first_seen\": %.6f,\n", r->first_seen);
        fprintf(out, "      \"last_seen\": %.6f,\n",  r->last_seen);

        if (r->type == DETECTION_PORT_SCAN) {
            fprintf(out, "      \"port_count\": %u,\n", r->port_count);
        }
        if (r->type == DETECTION_DNS_TUNNEL && r->dns_query[0] != '\0') {
            fprintf(out, "      \"dns_query\": \"");
            json_escape(out, r->dns_query);
            fprintf(out, "\",\n");
        }

        fprintf(out, "      \"description\": \"");
        json_escape(out, r->description);
        fprintf(out, "\"\n    }");
    }

    fprintf(out, "%s  ]\n}\n", count > 0 ? "\n" : "");
    return 0;
}
