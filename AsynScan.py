#!/usr/bin/env python3

"""
This is Python Asyncio AsynScan Port scanner

"""
import asyncio
import socket
import sys
from datetime import datetime
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
    width=80,                 
    box=box.ROUNDED,          
    border_style="green",     
    style="on blue"          
)


COMMON_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH/SFTP",
    115: "SFTP",
    548: "AFP",
    873: "Rsync",
    2049: "NFS",

    23: "Telnet",
    830: "NETCONF-SSH",
    831: "NETCONF-TLS",
    3389: "RDP",
    4899: "Radmin",
    5900: "VNC",
    5901: "VNC-1",
    5902: "VNC-2",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",

    25:   "SMTP",
    110:  "POP3",
    143:  "IMAP",
    465:  "SMTPS",
    587:  "SMTP-Submission",
    993:  "IMAPS",
    995:  "POP3S",
    2525: "SMTP-Alt",

    80:   "HTTP",
    443:  "HTTPS",
    3000: "Dev/Node/Grafana",
    4000: "Dev",
    4200: "Angular-Dev",
    5000: "Flask/Dev",
    7000: "Dev",
    8000: "HTTP-Dev",
    8008: "HTTP-Alt",
    8080: "HTTP-Alt",
    8081: "HTTP-Alt2",
    8082: "HTTP-Alt3",
    8090: "HTTP-Alt4",
    8443: "HTTPS-Alt",
    8888: "Jupyter/HTTP-Alt",
    9090: "Prometheus/HTTP-Alt",

    53:  "DNS",
    179: "BGP",
    514: "Syslog",

    88:    "Kerberos",
    111:   "RPC",
    135:   "MSRPC",
    139:   "NetBIOS-SSN",
    389:   "LDAP",
    445:   "SMB",
    464:   "Kerberos-KPW",
    636:   "LDAPS",
    3268:  "LDAP-GC",
    3269:  "LDAPS-GC",
    5722:  "DFSR",
    49152: "WinRPC-Dynamic",

    1433:  "MSSQL",
    1434:  "MSSQL-Browser",
    1521:  "Oracle",
    1830:  "Oracle-Alt",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    5433:  "PostgreSQL-Alt",
    5439:  "Redshift",
    5984:  "CouchDB",
    6379:  "Redis",
    6380:  "Redis-TLS",
    7474:  "Neo4j-HTTP",
    7687:  "Neo4j-Bolt",
    8086:  "InfluxDB",
    8087:  "Riak",
    9042:  "Cassandra",
    9160:  "Cassandra-Thrift",
    9200:  "Elasticsearch-HTTP",
    9300:  "Elasticsearch-Transport",
    26257: "CockroachDB",
    27017: "MongoDB",
    27018: "MongoDB-Shard",
    27019: "MongoDB-Config",
    28015: "RethinkDB",

    1883:  "MQTT",
    4369:  "RabbitMQ-EPMD",
    5671:  "AMQPS",
    5672:  "AMQP",
    6650:  "Pulsar",
    9092:  "Kafka",
    9093:  "Kafka-TLS",
    9094:  "Kafka-Alt",
    61613: "ActiveMQ-STOMP",
    61614: "ActiveMQ-STOMP-TLS",
    61616: "ActiveMQ",

    2181:  "ZooKeeper",
    2375:  "Docker-HTTP",
    2376:  "Docker-TLS",
    2377:  "Docker-Swarm",
    4001:  "etcd-Client",
    4243:  "Docker-Alt",
    6443:  "K8s-API",
    8500:  "Consul-HTTP",
    8501:  "Consul-HTTPS",
    8600:  "Consul-DNS",
    10250: "Kubelet-API",
    10255: "Kubelet-ReadOnly",
    10256: "Kube-Proxy",
    10257: "Kube-Controller",
    10259: "Kube-Scheduler",
    2379:  "etcd-Client",
    2380:  "etcd-Peer",

    1080:  "SOCKS",
    4444:  "Metasploit",
    4445:  "Metasploit-Alt",
    6666:  "IRC/Malware",
    6667:  "IRC",
    6668:  "IRC-Alt",
    6669:  "IRC-Alt",
    7777:  "Backdoor-Common",
    8181:  "Malware-Alt",
    31337: "Elite/Back-Orifice",

    3100:  "Loki",
    4317:  "OTLP-gRPC",
    4318:  "OTLP-HTTP",
    9091:  "Pushgateway",
    9100:  "Node-Exporter",
    9104:  "MySQL-Exporter",
    9187:  "Postgres-Exporter",
    9216:  "MongoDB-Exporter",
    14268: "Jaeger-HTTP",
    14250: "Jaeger-gRPC",
    16686: "Jaeger-UI",
    55680: "OpenTelemetry",

    43:   "WHOIS",
    79:   "Finger",
    102:  "MMS/S7",
    194:  "IRC",
    220:  "IMAP3",
    264:  "BGMP",
    366:  "ODMR",
    443:  "HTTPS",
    631:  "IPP",
    749:  "Kerberos-Admin",
    902:  "VMware-Auth",
    903:  "VMware-UI",
    1194: "OpenVPN-TCP",
    1723: "PPTP",
    1812: "RADIUS-Auth",
    1813: "RADIUS-Acct",
    6000: "X11",
    6001: "X11-1",
    9418: "Git",
    11211: "Memcached",
}

from rich.console import Console

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
       
        try:
            loop = asyncio.get_event_loop()
            info = await loop.getaddrinfo(self.target, None, family=socket.AF_INET)
            self.resolved_ip = info[0][4][0]
            return self.resolved_ip

        except socket.gaierror as e:
            print(f"Failed to resolve {self.target}: {e}")
            sys.exit(1)
        except KeyboardInterrupt as e:
            print("exit....")
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
        # Console().print(f"  Open ports: [green]{len(open_ports)}[/green]/{len(ports)}")
        self.results = {
            "target": self.target,
            "ip": self.resolved_ip,
            "scan_time": round(elapsed, 2),
            "total_ports": len(ports),
            "open": open_ports,
            "timestamp": datetime.now().isoformat(),
        }

        print("─" * 60)
        print(f"  Scan complete in {elapsed:.2f}s")
        print(f"  Open ports: {len(open_ports)}/{len(ports)}")
        return self.results
    def save_json(self, filename: str):
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n  [+] Results saved to {filename}")


def parse_ports(port_str: str) -> list:
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
        description="AsynScan Fast async port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 %(prog)s 192.168.1.1
  python3 %(prog)s example.com -p 80,443,8080
  python3 %(prog)s 10.0.0.1 -p 1-1024 --timeout 2 -c 200
  python3 %(prog)s scanme.nmap.org --top100 -o results.json
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

    if args.full:
        ports = list(range(1, 65536))
    elif args.top1000:
        ports = list(range(1, 1001))
    elif args.top100:
        ports = sorted(list(COMMON_PORTS.keys()))[:100]
    elif args.ports:
        ports = parse_ports(args.ports)
    else:
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
