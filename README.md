# pcap-analyzer

![Language](https://img.shields.io/badge/language-C11-blue.svg)
![Library](https://img.shields.io/badge/library-libpcap-green.svg)
![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)

A fast, lightweight network capture analyser written in C that reads `.pcap`
files via **libpcap**, detects common attack patterns, and produces a structured
**JSON report** ready to be consumed by
[threat-correlation-engine](https://github.com/vincent-p-essy/threat-correlation-engine).

---

## Features

- **Port-scan detection** — identifies SYN-scan bursts hitting many distinct
  ports within a configurable time window.
- **ARP-spoofing detection** — flags MAC addresses that announce different IP
  addresses over time.
- **DNS-tunneling detection** — spots unusually long DNS label names that are
  typical of data-exfiltration through DNS.
- Zero external dependencies beyond libpcap.
- Output JSON is machine-readable and directly consumed by
  `threat-correlation-engine`.

---

## Prerequisites

| Dependency | Minimum version | Install (Debian/Ubuntu) |
|------------|----------------|-------------------------|
| GCC        | 7.x            | `apt install gcc`       |
| libpcap    | 1.9            | `apt install libpcap-dev` |
| make       | 4.x            | `apt install make`      |

---

## Installation & Compilation

```bash
# Clone the repository
git clone https://github.com/vincent-p-essy/pcap-analyzer.git
cd pcap-analyzer

# Build
make

# Run the test suite
make test

# Clean build artefacts
make clean
```

The binary is placed at `./pcap-analyzer`.

---

## Usage

```
Usage: ./pcap-analyzer [OPTIONS] <capture.pcap>

Options:
  -o <file>    Write JSON report to <file> (default: stdout)
  -t <sec>     Port-scan time window in seconds (default: 10)
  -p <count>   Port-scan threshold: distinct ports in window (default: 15)
  -l <len>     DNS label max length before alert (default: 40)
  -h           Show this help message
```

### Examples

```bash
# Analyse a capture and print the JSON report to stdout
./pcap-analyzer capture.pcap

# Write the report to a file
./pcap-analyzer -o report.json capture.pcap

# Tighter port-scan detection: 10 ports in 5 seconds
./pcap-analyzer -t 5 -p 10 -o report.json capture.pcap

# Stricter DNS label threshold
./pcap-analyzer -l 30 capture.pcap
```

---

## JSON Output Format

The report produced by `pcap-analyzer` is designed to be consumed by
**threat-correlation-engine** without additional transformation.

```json
{
  "source_file": "capture.pcap",
  "generated_at": "2024-01-15T10:30:00Z",
  "alert_count": 2,
  "alerts": [
    {
      "type": "PORT_SCAN",
      "severity": "HIGH",
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.1",
      "first_seen": 1705312200.123000,
      "last_seen": 1705312205.456000,
      "port_count": 23,
      "description": "SYN scan detected: 23 distinct ports in 5.33s from 192.168.1.100 to 10.0.0.1"
    },
    {
      "type": "ARP_SPOOF",
      "severity": "CRITICAL",
      "src_ip": "192.168.1.254",
      "dst_ip": "192.168.1.2",
      "first_seen": 1705312210.000000,
      "last_seen": 1705312210.000000,
      "description": "ARP spoofing detected: MAC de:ad:be:ef:00:01 previously announced 192.168.1.1, now announces 192.168.1.254"
    }
  ]
}
```

### Severity levels

| Detection type | Severity |
|---------------|----------|
| PORT_SCAN     | HIGH     |
| ARP_SPOOF     | CRITICAL |
| DNS_TUNNEL    | MEDIUM   |

---

## Code Architecture

```
pcap-analyzer/
├── src/
│   ├── main.c        Entry point, CLI argument parsing (getopt)
│   ├── parser.h/.c   libpcap wrapper — Ethernet/IP/TCP/UDP/ARP decoding
│   ├── detector.h/.c Attack pattern detectors (port scan, ARP spoof, DNS tunnel)
│   └── reporter.h/.c JSON report writer (no external JSON library)
├── tests/
│   ├── test_detector.c  Unit tests with fake capture stubs
│   └── samples/         Synthetic .pcap files for manual testing
├── Makefile
└── README.md
```

### Module responsibilities

| File | Role |
|------|------|
| `parser.h/.c` | Wraps `pcap_open_offline` / `pcap_next_ex`. Decodes Ethernet frames into `packet_t`. Handles IP fragmentation header offsets, ARP, TCP, UDP. |
| `detector.h/.c` | Stateful detectors. Maintains per-IP port tracking tables and per-MAC ARP tables. Accumulates `detection_result_t` via `realloc`. |
| `reporter.h/.c` | Serialises `detection_result_t[]` to JSON. Uses only `stdio.h` and `time.h`. JSON strings are escaped inline. |
| `main.c` | Glue: parses CLI flags, calls `parser_open` → `detector_run` → `reporter_write_json` → `detector_free` → `parser_close`. |

---

## Detectors

### Port Scan (PORT_SCAN)

Tracks TCP SYN packets (flag `0x02`, no ACK) per source IP. Maintains a
sliding window of `port_scan_window_sec` seconds. When a single source hits
`port_scan_threshold` or more **distinct** destination ports within that window,
an alert is raised.

**Configurable parameters:**
- `-t <sec>` — time window (default: 10 s)
- `-p <count>` — distinct-port threshold (default: 15)

### ARP Spoofing (ARP_SPOOF)

Builds a MAC→IP table from ARP request/reply packets. When a MAC address
previously seen announcing IP _A_ sends a new ARP packet announcing IP _B_
(where _A_ ≠ _B_), an alert is raised.

This catches both gratuitous ARP attacks and classic man-in-the-middle
scenarios.

### DNS Tunneling (DNS_TUNNEL)

Inspects UDP packets on port 53. Decodes the QNAME field label by label. If
any single label exceeds `dns_label_max_len` characters, it is flagged as
suspicious — DNS tunneling tools (iodine, dnscat2) encode data as extremely
long subdomain labels.

**Configurable parameter:**
- `-l <len>` — label length threshold (default: 40)

---

## Integration with threat-correlation-engine

`pcap-analyzer` is designed as a **data producer** in a broader security
pipeline. The JSON it emits follows a schema that `threat-correlation-engine`
can ingest directly:

```bash
# Typical pipeline usage
./pcap-analyzer -o /tmp/alerts.json capture.pcap
threat-correlation-engine --input /tmp/alerts.json
```

The `generated_at` ISO-8601 timestamp, `severity` field, and `src_ip`/`dst_ip`
dotted-notation fields are all designed to match the schema expected by the
correlation engine.

---

## Roadmap

- [ ] IPv6 support
- [ ] VLAN (802.1Q) tag stripping
- [ ] ICMP flood detection
- [ ] Live capture mode (`pcap_open_live`)
- [ ] Configurable output format (JSON / CSV / syslog)
- [ ] Rule file for custom thresholds per source subnet
- [ ] Multi-threaded packet processing for large captures

---

## Author

**Vincent Plessy** — [vincent.plessy12@gmail.com](mailto:vincent.plessy12@gmail.com)

Contributions and issue reports are welcome.
