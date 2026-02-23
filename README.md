# Professional Network Scanner

A concurrent TCP-based network scanner for discovering live hosts and open ports within a CIDR subnet.

## Features

- TCP-based host discovery (no ARP, no raw sockets)
- Concurrent port scanning
- JSON output support
- Markdown report generation
- Cross-platform (Windows, Linux, macOS)
- Docker compatible
- No root/admin privileges required

---

## How It Works

### Host Discovery

Live hosts are identified using TCP connect probes on common service ports:

- 22 (SSH)
- 80 (HTTP)
- 443 (HTTPS)

If a TCP connection succeeds on any probe port, the host is considered live.

> Note: Hosts with no open ports in the probe list may not be detected.

---

## Installation (Local)

Requires Python 3.11+

No external dependencies.

Run:

```bash
python scanner.py 192.168.0.0/24
