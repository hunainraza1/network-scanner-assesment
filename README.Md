#Network Scanner

A lightweight, professional-grade network scanner written in Python. It performs host discovery via Scapy and fast TCP port scanning using concurrent sockets.

## Features

- **Host Discovery**: Uses Scapy (ICMP/ARP) to identify live hosts.
- **Port Scanning**: Multi-threaded TCP socket scanning.
- **Concurrency**: High performance using `concurrent.futures`.
- **Reporting**: Outputs structured JSON and Markdown reports.
- **Type Hinting**: Fully typed for robustness.

## Prerequisites

- Python 3.11+
- Root/Administrator privileges (required for raw socket access by Scapy).

## Local Installation

1. Install dependencies:
   ```bash
   pip install -r requirements.txt

Note for Windows Users: Ensure Npcap is installed for Scapy to interact with the network adapter.