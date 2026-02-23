#!/usr/bin/env python3
"""
Network Scanner Tool

A professional CLI tool to scan CIDR subnets for live hosts and open TCP ports.
Uses Scapy for host discovery and Socket/Threading for port scanning.

Author: Senior Security Engineer
Version: 1.0.0
"""

import argparse
import json
import socket
import sys
import time
from datetime import datetime
from ipaddress import IPv4Network
from typing import Dict, List, Optional, Tuple

from scapy.all import ICMP, IP, sr, srp, ARP, Ether


import concurrent.futures

# Default Top 20 Ports
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
]

class NetworkScanner:
    """Handles network discovery and port scanning operations."""

    def __init__(self, cidr: str, ports: Optional[List[int]] = None, timeout: int = 2):
        """
        Initialize the scanner.

        Args:
            cidr: CIDR notation string (e.g., "192.168.1.0/24").
            ports: List of ports to scan. Defaults to DEFAULT_PORTS.
            timeout: Socket timeout in seconds.
        """
        try:
            self.network = IPv4Network(cidr, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR provided: {e}")

        self.ports = ports if ports else DEFAULT_PORTS
        self.timeout = timeout
        self.results = {
            "scan_metadata": {
                "target_cidr": cidr,
                "scan_start_time": "",
                "scan_end_time": "",
                "ports_scanned": self.ports,
                "total_ips_in_range": self.network.num_addresses - 2  # Exclude network/broadcast
            },
            "live_hosts": []
        }

    def discover_hosts(self) -> List[str]:
        """Identifies live hosts using ARP (much more reliable for local subnets)."""
        print(f"[*] Starting ARP Discovery on {self.network}...")
        
        # Create an ARP Broadcast packet
        # Ether(dst="ff:ff:ff:ff:ff:ff") ensures it goes to everyone on the local net
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(self.network))
        
        # srp = Send and Receive packets at Layer 2
        ans, unans = srp(arp_request, timeout=self.timeout, verbose=0)
        
        live_ips = []
        for sent, received in ans:
            live_ips.append(received.psrc)

        print(f"[+] Discovered {len(live_ips)} live hosts.")
        return live_ips

    def _scan_single_port(self, ip: str, port: int) -> Optional[int]:
        """
        Scans a single port on a specific IP using TCP Socket.

        Args:
            ip: Target IP address.
            port: Target port number.

        Returns:
            Port number if open, None otherwise.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return port
        except socket.error:
            pass
        return None

    def scan_ports(self, live_ips: List[str]) -> None:
        """
        Scans ports on live hosts using ThreadPoolExecutor for concurrency.

        Args:
            live_ips: List of active IP addresses.
        """
        print(f"[*] Scanning ports on {len(live_ips)} hosts...")
        
        # Structure: { "192.168.1.1": [22, 80], "192.168.1.2": [] }
        open_ports_map: Dict[str, List[int]] = {ip: [] for ip in live_ips}

        # Use ThreadPoolExecutor for I/O bound socket operations
        # Adjust max_workers based on network capacity
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            # Create a future for every (IP, Port) pair
            future_to_ep = {
                executor.submit(self._scan_single_port, ip, port): (ip, port) 
                for ip in live_ips for port in self.ports
            }

            for future in concurrent.futures.as_completed(future_to_ep):
                ip, port = future_to_ep[future]
                try:
                    result = future.result()
                    if result:
                        open_ports_map[ip].append(result)
                except Exception as e:
                    # Handle exceptions silently to keep scan robust
                    pass

        # Format results
        for ip, ports in open_ports_map.items():
            if ports:
                # Sort ports numerically
                ports.sort()
                print(f"    [+] {ip}: Open ports {ports}")
                
                host_entry = {
                    "ip": ip,
                    "open_ports": ports,
                    "port_count": len(ports)
                }
                self.results["live_hosts"].append(host_entry)

    def run(self) -> Dict:
        """
        Executes the full scan workflow.

        Returns:
            Dictionary containing scan results.
        """
        start_time = datetime.now()
        self.results["scan_metadata"]["scan_start_time"] = start_time.isoformat()

        try:
            live_ips = self.discover_hosts()
            if live_ips:
                self.scan_ports(live_ips)
            else:
                print("[!] No live hosts found.")
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user.")
            sys.exit(1)
        finally:
            end_time = datetime.now()
            self.results["scan_metadata"]["scan_end_time"] = end_time.isoformat()
            
        return self.results

    def save_json(self, filename: str = "scan_results.json") -> None:
        """Saves results to a JSON file."""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        print(f"[+] Results saved to {filename}")

    def generate_report(self, filename: str = "report.md") -> None:
        """
        Generates a Markdown report summarizing the findings.
        """
        md_lines = [
            f"# Network Scan Report",
            f"",
            f"**Target:** {self.results['scan_metadata']['target_cidr']}",
            f"**Scan Time:** {self.results['scan_metadata']['scan_start_time']}",
            f"**Total Live Hosts:** {len(self.results['live_hosts'])}",
            f"",
            "## Summary Table",
            "",
            "| IP Address | Open Ports | Count |",
            "|------------|------------|-------|"
        ]

        for host in self.results["live_hosts"]:
            ports_str = ", ".join(map(str, host["open_ports"]))
            md_lines.append(f"| {host['ip']} | {ports_str} | {host['port_count']} |")

        with open(filename, 'w') as f:
            f.write("\n".join(md_lines))
        
        print(f"[+] Markdown report generated: {filename}")


def main():
    """Main entry point for CLI usage."""
    parser = argparse.ArgumentParser(
        description="Professional Network Scanner (Host Discovery & Port Scan)"
    )
    parser.add_argument("cidr", help="Target CIDR (e.g., 192.168.1.0/24)")
    parser.add_argument(
        "-p", "--ports", 
        nargs="+", 
        type=int, 
        help="Space separated list of ports to scan (default: Top 20)"
    )
    parser.add_argument(
        "-t", "--timeout", 
        type=int, 
        default=2, 
        help="Timeout for connections in seconds (default: 2)"
    )
    parser.add_argument(
        "--json", 
        action="store_true", 
        help="Save output as JSON (scan_results.json)"
    )
    parser.add_argument(
        "--report", 
        action="store_true", 
        help="Generate Markdown report (report.md)"
    )

    args = parser.parse_args()

    # Validate Ports
    ports = args.ports if args.ports else DEFAULT_PORTS

    try:
        scanner = NetworkScanner(args.cidr, ports=ports, timeout=args.timeout)
        scanner.run()
        
        if args.json:
            scanner.save_json()
        
        if args.report or (not args.json and not args.report): 
            # Default to report if nothing specified, or if --report flag is passed
            scanner.generate_report()

    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

# Import here to ensure type checking works or lazy loading if needed

if __name__ == "__main__":
    main()