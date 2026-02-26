

# Network Scanner (TCP-Based Host Discovery and Port Scanner)

## Overview

This project is a Python-based network scanner that performs:

* TCP-based host discovery within a specified CIDR range
* Multi-port scanning on discovered live hosts
* Automatic generation of scan results in JSON format
* Automatic generation of a Markdown report
* Cross-platform support (Windows, Linux, Docker)

The scanner is designed to work reliably in environments where ARP-based discovery may fail, such as Docker containers or restricted network environments.

---

## Features

* CIDR network scanning (example: 192.168.0.0/24)
* TCP connect-based host discovery
* Multi-threaded port scanning for speed
* JSON output for structured data processing
* Markdown report generation for readability
* Docker support for consistent execution across systems
* No external Python dependencies required

---

## How It Works

The scanner performs the following steps:

1. Accepts a CIDR network range as input
2. Attempts TCP connections on common ports to identify live hosts
3. Identifies hosts that respond successfully
4. Scans selected ports on each live host
5. Stores results in:

   * scan_results.json
   * report.md

---

## Project Structure

```
network-scanner/
│
├── scanner.py           # Main scanner script
├── install.bat          # Windows installation and execution helper
├── Dockerfile           # Docker configuration
├── README.md            # Documentation
│
├── scan_results.json    # Generated scan results
└── report.md            # Generated Markdown report
```

---

## Requirements

### Native execution

* Python 3.8 or newer (python 3.11 was used natively)

Verify installation:

```
python --version
```

No external libraries are required.

---

## Running the Scanner (Native Python)

### Default network scan

```
python scanner.py
```

Example output:

```
[*] Starting TCP-based host discovery on 192.168.0.0/24...
[+] Discovered 2 live hosts.

[*] Scanning ports on discovered hosts...

[+] 192.168.0.1: Open ports [53, 80]
[+] 192.168.0.160: Open ports [23, 80]

[+] Results saved to scan_results.json
[+] Markdown report generated: report.md
```

---

## Running Using install.bat (Windows)

Simply double-click:

```
install.bat
```

This will:

* Verify Python installation
* Execute the scanner
* Generate result files

---

## Running with Docker

Docker allows the scanner to run in an isolated Linux environment.

---

### Step 1: Build the Docker image

Open terminal in the project directory:

```
docker build -t network-scanner .
```

---

### Step 2: Run the scanner

```
docker run --rm network-scanner
```

Example output:

```
[*] Starting TCP-based host discovery on 192.168.0.0/24...
[+] Discovered 2 live hosts.

[*] Scanning ports on 2 hosts...

[+] 192.168.0.1: Open ports [53, 80]
[+] 192.168.0.160: Open ports [23, 80]

[+] Results saved to scan_results.json
[+] Markdown report generated: report.md
```

---

## Accessing Output Files When Using Docker

By default, files generated inside Docker are removed when the container exits.

To save results to your host machine, run:

Windows PowerShell:

```
docker run --rm -v ${PWD}:/app network-scanner
```

Linux / Mac:

```
docker run --rm -v $(pwd):/app network-scanner
```

This will generate files in your current directory:

```
scan_results.json
report.md
```

---

## Example scan_results.json

```
{
  "192.168.0.1": [53, 80],
  "192.168.0.160": [23, 80]
}
```

---

## Example report.md

```
# Network Scan Report

## Live Hosts and Open Ports

- 192.168.0.1
  - Port 53: Open
  - Port 80: Open

- 192.168.0.160
  - Port 23: Open
  - Port 80: Open
```

---

## Why TCP-Based Discovery Instead of ARP

ARP-based host discovery works only within local network segments and often requires elevated privileges.

In containerized environments such as Docker:

* ARP requests may not function correctly
* Network isolation prevents ARP broadcasts
* Results may show zero live hosts

TCP-based discovery was selected because it:

* Works reliably across different environments
* Works inside Docker containers
* Does not require special permissions
* Provides consistent and portable results

---

## Use Cases

This scanner can be used for:

* Network discovery
* Lab environments
* Security testing and learning
* Identifying active hosts
* Identifying open ports
* Educational purposes

---

## Example Use Case 1: Home Network Scan

Command:

```
python scanner.py
```

Output:

```
Discovered:
192.168.0.1
192.168.0.160
```

---

## Example Use Case 2: Docker Execution

Command:

```
docker run --rm network-scanner
```

Output:

```
Discovered live hosts and open ports
Generated scan_results.json
Generated report.md
```

---

## Reliability and Compatibility

Tested on:

* Windows 10 / 11
* Docker (Linux container)
* Clean systems without preinstalled dependencies

Produces consistent and reliable results across environments.

---

## Author

Hunain Ali



