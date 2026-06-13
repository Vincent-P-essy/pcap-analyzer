#ifndef REPORTER_H
#define REPORTER_H

#include <stdio.h>
#include <stddef.h>
#include "detector.h"

/**
 * Write a JSON report to the given FILE stream.
 *
 * @param out      Destination stream (e.g. stdout or an opened file).
 * @param filename Path of the analysed pcap file (informational).
 * @param results  Array of detection_result_t produced by detector_run().
 * @param count    Number of elements in results.
 * @return 0 on success, -1 on write error.
 */
int reporter_write_json(FILE *out,
                        const char *filename,
                        const detection_result_t *results,
                        size_t count);

#endif /* REPORTER_H */
