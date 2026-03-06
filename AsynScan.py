#!/usr/bin/env python3

"""
This is Python Asyncio AsynScan Port scanner

"""
import asyncio
import socket
import sys
import argparse
import time
import json
from rich import print
from rich.panel import Panel
from rich import box
banner = """
╔═══════════════════════════════════════╗
║      Asynscan PORT SCANNER v1.0       ║
║      github.com/lokesh32t/AsynScan    ║
╚═══════════════════════════════════════╝
"""
panel = Panel(
    banner,
    title="[cyan]Port Scanner[/cyan]",
    subtitle="[magenta]Lokesh Bhati[/magenta]",
    width=80,                 # Fixed width
    box=box.ROUNDED,          # Border style
    border_style="green",     # Border color
    style="on blue"          # Background color
)


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP",
    631: "IPP", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 2181: "ZooKeeper", 3000: "Dev/Node",
    3306: "MySQL", 3389: "RDP", 4444: "Metasploit", 5000: "Flask",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6379: "Redis", 6443: "K8s API", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9200: "Elasticsearch", 9300: "Elasticsearch", 27017: "MongoDB",
}

from rich.console import Console
from rich.table import Table

###########################################


class AsynScan():
    def __init__(self, target, timeout: float = 1.0, concurrency: int = 100, banner_grab: bool = True, verbose: bool = False):
        self.target = target
        self.timeout = timeout
        self.concurrency = concurrency
        self.banner_grab = banner_grab
        self.verbose = verbose
        self.results = {}
        self.semaphore = None
        self.resolved_ip = None

    async def resolve_ip(self):
        """
            Convert Hostname to IP Address
        """
        try:
            loop = asyncio.get_event_loop()
            info = await loop.getaddrinfo(self.target, None, family=socket.AF_INET)
            self.resolved_ip = info[0][4][0]
            return self.resolved_ip

        except socket.gaierror as e:
            print(f"Failed to resolve {self.target}: {e}")
            sys.exit(1)
        except KeyboardInterrupt as e:
            print("df")
            sys.exit(1)

    async def grab_banner(self, port, reader: asyncio.StreamReader):
        try:
            probes = {
                80: b"HEAD / HTTP/1.0\r\n\r\n",
                443: b"HEAD / HTTP/1.0\r\n\r\n",
                8080: b"HEAD / HTTP/1.0\r\n\r\n",
                21: None, 22: None, 25: None, 110: None, 143: None,
            }
            probe = probes.get(port, b"\r\n")
            if probe:
                reader._transport.write(probe)
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            banner = data.decode('utf-8', errors='ignore').strip()
            banner = banner.replace('\n', ' ').replace('\r', '')[:80]
            return banner if banner else None

        except Exception:
            return None

    async def scan_port(self, port: int):
        """For Scan A single Port at a time """
        async with self.semaphore:
            result = {
                "port": port,
                "state": "closed",
                "service": COMMON_PORTS.get(port, "unknown"),
                "banner": None,
                "latency_ms": None,
            }
            start = time.monotonic()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.resolved_ip, port),
                    timeout=self.timeout
                )
                latency = (time.monotonic() - start) * 1000
                result["state"] = "open"
                result["latency_ms"] = round(latency, 2)

                if self.banner_grab:
                    banner = await self.grab_banner(port, reader)
                    result["banner"] = banner

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                except KeyboardInterrupt as e:

                    print("quiting")
                    sys.exit(1)
            except asyncio.TimeoutError:
                result["state"] = "filtered"
            except ConnectionRefusedError:
                result["state"] = "closed"
            except OSError:
                result["state"] = "filtered"
            except KeyboardInterrupt as e:
                print("quiting")
                sys.exit(1)

            if self.verbose or result["state"] == "open":
                self.print_result(result)
            return result

    def print_result(self, result: dict):
        """Print Port scan Result immediately as each port is scanned"""
        console = Console()
        state = result["state"]
        if state == 'open':
            banner = f" | {result['banner']}" if result['banner'] else ""
            console.print(f"  [green][OPEN][/green]   {result['port']:>5}/tcp  {result['service']:<16} ({result['latency_ms']}ms){banner}")
        elif self.verbose:
            console.print(f"  [grey50][{state.upper()}][/grey50]  {result['port']:>5}/tcp  {result['service']}")

    async def scan(self, ports: list):
        self.semaphore = asyncio.Semaphore(self.concurrency)
        print(panel)
        print("\n")
        await self.resolve_ip()
        print(f"  Target  : {self.target} ({self.resolved_ip})")
        print(f"  Ports   : {len(ports)} ports")
        print(f"  Timeout : {self.timeout}s  |  Concurrency: {self.concurrency}")
        print("─" * 60)
        start_time = time.monotonic()
        tasks = [self.scan_port(p) for p in ports]
        results = await asyncio.gather(*tasks)
        elapsed = time.monotonic() - start_time

       

        open_ports = [r for r in results if r and r["state"] == "open"]
        print("─" * 60)
        Console().print(f"  Open ports: [green]{len(open_ports)}[/green]/{len(ports)}")


def parse_ports(port_str: str) -> list:
    """Parse port ranges like '80,443,1000-2000'."""
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-', 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def main():
    parser = argparse.ArgumentParser(
        description="Fast async port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python AsynScan.py 192.168.1.1
  python AsynScan.py example.com -p 80,443,8080
  python AsynScan.py 10.0.0.1 -p 1-1024 --timeout 2 -c 200
  python AsynScan.py scanme.nmap.org --top100 -o results.json
        """
    )
    parser.add_argument("target", help="Target host or IP address")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g. 80,443,1000-2000)", default=None)
    parser.add_argument("--top100", action="store_true", help="Scan top 100 common ports")
    parser.add_argument("--top1000", action="store_true", help="Scan top 1000 common ports")
    parser.add_argument("--full", action="store_true", help="Scan all 65535 ports")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout per port (default: 1.0)")
    parser.add_argument("-c", "--concurrency", type=int, default=500, help="Concurrent connections (default: 500)")
    parser.add_argument("--no-banner", action="store_true", help="Disable banner grabbing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all port states")
    parser.add_argument("-o", "--output", help="Save results to JSON file")

    args = parser.parse_args()

    # Determine ports to scan
    if args.full:
        ports = list(range(1, 65536))
    elif args.top1000:
        ports = list(range(1, 1001))
    elif args.top100:
        ports = sorted(list(COMMON_PORTS.keys()))[:100]
    elif args.ports:
        ports = parse_ports(args.ports)
    else:
        # Default: common ports
        ports = sorted(COMMON_PORTS.keys())

    scanner = AsynScan(
        target=args.target,
        timeout=args.timeout,
        concurrency=args.concurrency,
        banner_grab=not args.no_banner,
        verbose=args.verbose
    )

    results = asyncio.run(scanner.scan(ports))

    if args.output:
        scanner.save_json(args.output)


if __name__ == "__main__":
    main()
