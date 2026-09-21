# DDoS Protector: SDN-based DDoS Detection and Mitigation (Mininet + Ryu)

Lightweight SDN project that detects volumetric DDoS-style traffic using packet-count thresholds and source-IP entropy, then mitigates attacking sources with OpenFlow drop rules.

Built and evaluated within a Mininet + Ryu + Open vSwitch environment.

## Features
- Custom tree topology (1 controller, 3 switches, 20 hosts)
- Reactive Ryu controller with Packet-In handling
- Threshold-based detection (per-source packet counts)
- Entropy-based detection (source-IP distribution)
- Automated mitigation using high-priority OpenFlow drop rules (`idle_timeout=30`)
- Scapy script for TCP SYN flood generation

## Repository Contents
| File | Description |
|------|-------------|
| `ddos_topo_20.py` | Mininet topology script (3 switches, 20 hosts) |
| `simple_detector2.py` | Ryu controller app (detection + mitigation) |
| `syn_flood.py` | Scapy TCP SYN flood generator |

## Requirements
- Mininet VM (Ubuntu)
- Ryu controller
- Open vSwitch
- Python 3
- Scapy, hping3, iperf3 (for traffic generation/testing)

## Topology
- **Victim / server:** `h1` → `10.0.0.1`
- **Legitimate clients:** `h2`–`h15`
- **Attack hosts:** `h16`–`h20`
- **Controller:** Ryu on OpenFlow port `6633`

## Quick Start

### 1. Start the controller
```bash
ryu-manager simple_detector2.py
```
### 2. Start the topology (new terminal)
```Bash
sudo python3 ddos_topo_20.py
```
### 3. Generate legitimate traffic
```Bash
mininet> h1 iperf3 -s &
mininet> h10 iperf3 -c 10.0.0.1 -t 30
```
### 4. Generate a Scapy SYN flood (from an attack host)
```Bash
mininet> h16 python3 syn_flood.py
```
### 5. Verify mitigation
```Bash
mininet> sh sudo ovs-ofctl dump-flows s3
```

### Detection Logic
- 5 second monitoring interval
- Threshold: > 15,000 packets from a source IP
- Entropy: alert when source-IP entropy < 0.6 and total packets in interval > 2,000
- Mitigation: install OpenFlow rule priority=100, ip, nw_src=<attacker> actions=drop with idle_timeout=30

### Evaluation Summary
Experiments included baseline traffic and attack categories (ICMP, UDP, TCP SYN via hping3, Scapy SYN, multi-attacker ICMP).
- High-rate floods (hping3 / multi-attacker): 100% detection
- Scapy SYN (lower rate): lower detection rate (threshold often not crossed)
- Multi-attacker ICMP: fastest average detection
- Legitimate throughput degraded under attack; mitigation confirmed via flow-table inspection
