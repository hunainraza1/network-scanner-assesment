

import argparse
import json
import socket
import sys
import concurrent.futures
from datetime import datetime
from ipaddress import IPv4Network
from typing import Dict, List, Optional

# Default Top 20 Ports
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
]


class NetworkScanner:
    

    def __init__(self, cidr: str, ports: Optional[List[int]] = None, timeout: int = 2):
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
                "total_ips_in_range": self.network.num_addresses - 2
            },
            "live_hosts": []
        }

    def discover_hosts(self) -> List[str]:
        
        print(f"[*] Starting TCP-based host discovery on {self.network}...")

        probe_ports = [22, 80, 443]
        live_ips = []

        def probe_ip(ip):
            for port in probe_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(self.timeout)
                        result = sock.connect_ex((str(ip), port))
                        if result == 0:
                            return str(ip)
                except socket.error:
                    continue
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(probe_ip, ip) for ip in self.network.hosts()]

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    live_ips.append(result)

        live_ips.sort(key=lambda ip: tuple(map(int, ip.split("."))))

        print(f"[+] Discovered {len(live_ips)} live hosts.")
        return live_ips

    def _scan_single_port(self, ip: str, port: int) -> Optional[int]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    return port
        except socket.error:
            pass
        return None

    def scan_ports(self, live_ips: List[str]) -> None:
        print(f"[*] Scanning ports on {len(live_ips)} hosts...")

        open_ports_map: Dict[str, List[int]] = {ip: [] for ip in live_ips}

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
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
                except Exception:
                    pass

        for ip, ports in open_ports_map.items():
            if ports:
                ports.sort()
                print(f"    [+] {ip}: Open ports {ports}")

                self.results["live_hosts"].append({
                    "ip": ip,
                    "open_ports": ports,
                    "port_count": len(ports)
                })

    def run(self) -> Dict:
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
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"[+] Results saved to {filename}")

    def generate_report(self, filename: str = "report.md") -> None:
        """Generates a Markdown report summarizing the findings."""
        md_lines = [
            "# Network Scan Report",
            "",
            f"**Target:** {self.results['scan_metadata']['target_cidr']}",
            f"**Scan Start:** {self.results['scan_metadata']['scan_start_time']}",
            f"**Scan End:** {self.results['scan_metadata']['scan_end_time']}",
            f"**Total Live Hosts:** {len(self.results['live_hosts'])}",
            "",
            "## Summary Table",
            "",
            "| IP Address | Open Ports | Count |",
            "|------------|------------|-------|"
        ]

        for host in self.results["live_hosts"]:
            ports_str = ", ".join(map(str, host["open_ports"]))
            md_lines.append(
                f"| {host['ip']} | {ports_str} | {host['port_count']} |"
            )

        with open(filename, "w") as f:
            f.write("\n".join(md_lines))

        print(f"[+] Markdown report generated: {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="Professional Network Scanner (TCP Discovery & Port Scan)"
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
    ports = args.ports if args.ports else DEFAULT_PORTS

    try:
        scanner = NetworkScanner(args.cidr, ports=ports, timeout=args.timeout)
        scanner.run()

        if args.json:
            scanner.save_json()

        if args.report or (not args.json and not args.report):
            scanner.generate_report()

    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()