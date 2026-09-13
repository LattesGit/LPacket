# LPacket

A terminal based network packet analyzer inspired by Wireshark built with Python and Scapy. No GUI, no bloat a fast, full-screen `curses` interface that lists live packets, lets you drill into any packet's headers and hex dump filter by protocol/IP/port, and save or replay `.pcap` captures.

![status](https://img.shields.io/badge/status-active-brightgreen) ![python](https://img.shields.io/badge/python-3.8%2B-blue) ![license](https://img.shields.io/badge/license-MIT-lightgrey)

## Features

- Full-screen live capture view with auto-scrolling packet list
- Color-coded rows by protocol (TCP, UDP, ICMP, DNS, HTTP)
- Browse packets with arrow keys, open details with Enter
- Per-packet breakdown: Ethernet, IP, TCP/UDP/ICMP fields, raw hex + ASCII
- Filters: `filter tcp`, `filter ip <addr>`, `filter port <port>`, `filter src/dst <addr>`
- Live stats: protocol distribution, top source/destination IPs, top ports
- Save captures to `.pcap` and reload them later for offline analysis
- IPv4 and IPv6 support
- Single file, no external UI framework — just Python's standard `curses` and Scapy

## Requirements

- Linux (primary target — relies on raw sockets and `curses`)
- Python 3.8+
- Root/sudo privileges for live capture (not required for `-r` pcap analysis)

## Installation

```bash
git clone https://github.com/<your-username>/lpacket.git
cd lpacket
pip install -r requirements.txt
```

## Usage

Pick an interface interactively:

```bash
sudo python3 lpacket.py
```

Capture on a specific interface directly:

```bash
sudo python3 lpacket.py -i eth0
```

Analyze a previously saved capture (no root required):

```bash
python3 lpacket.py -r capture.pcap
```

Show all CLI options:

```bash
python3 lpacket.py --help
```

## Controls

| Key / Command | Action |
|---|---|
| `UP` / `DOWN` | browse the packet list |
| `ENTER` (empty input) | show details for the highlighted packet |
| `help` | list all commands |
| `start` / `stop` | start or pause capturing |
| `clear` | clear the packet buffer |
| `filter <type>` | apply a filter (`tcp`, `udp`, `icmp`, `dns`, `ip <addr>`, `port <n>`, `src <addr>`, `dst <addr>`) |
| `filter clear` | remove the active filter |
| `show <n>` | show details for packet number `n` |
| `stats` | protocol distribution and top talkers |
| `interfaces` | list available network interfaces |
| `save <file>` | save captured packets to a `.pcap` file |
| `load <file>` | load packets from a `.pcap` file |
| `quit` | exit |

## Scope

This tool is a packet **analyzer** only. It does not include packet injection, ARP spoofing, MITM, credential harvesting, traffic manipulation, or unauthorized scanning. It is intended for inspecting traffic on interfaces you own or are explicitly authorized to monitor.

## License

MIT see [LICENSE](LICENSE).
