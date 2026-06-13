# Test Samples

This directory is intended to hold `.pcap` sample files used during development
and testing of `pcap-analyzer`.

## Why samples are not committed

Pcap files can contain sensitive information (IP addresses, credentials, private
traffic). Only **synthetic** captures generated for testing purposes should ever
be committed here.

## Generating synthetic captures with tcpdump

### Port-scan traffic

Capture SYN packets from `nmap` running against localhost:

```bash
# Terminal 1 — start capture
sudo tcpdump -i lo -w tests/samples/port_scan.pcap tcp

# Terminal 2 — run a quick SYN scan
nmap -sS -p 1-100 127.0.0.1

# Stop capture with Ctrl-C in Terminal 1
```

### ARP traffic

Capture ARP traffic on the local network for 30 seconds:

```bash
sudo tcpdump -i eth0 -w tests/samples/arp.pcap arp -G 30 -W 1
```

To simulate ARP spoofing with `arpspoof` (requires `dsniff`):

```bash
# Spoof gateway 192.168.1.1 from 192.168.1.50
sudo arpspoof -i eth0 -t 192.168.1.50 192.168.1.1
```

### DNS traffic

Capture DNS queries:

```bash
sudo tcpdump -i eth0 -w tests/samples/dns.pcap 'udp port 53' -G 30 -W 1
```

To test DNS tunneling detection, use [iodine](https://github.com/yarrick/iodine)
or [dnscat2](https://github.com/iagox86/dnscat2) to generate tunneled traffic
with long encoded labels.

## Generating captures with Wireshark

1. Open Wireshark and select your network interface.
2. Apply a capture filter (e.g. `tcp`, `arp`, `udp port 53`).
3. Start capture, generate traffic, then stop.
4. Export via **File → Export Specified Packets** → choose `.pcap` format.

## Using the captures

```bash
# Analyse a sample file
./pcap-analyzer -o report.json tests/samples/port_scan.pcap

# Adjust thresholds for testing
./pcap-analyzer -t 5 -p 10 tests/samples/port_scan.pcap
```

## Pre-built samples from the community

- [Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures)
- [NETRESEC PCAP files](https://www.netresec.com/?page=PcapFiles)
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)

> **Warning**: downloaded captures from the internet may contain real attack
> traffic. Analyse them in an isolated environment.
