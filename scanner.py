#!/usr/bin/env python3
"""Fast async port scanner with service detection."""

import asyncio
import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass, asdict
from typing import List, Optional

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    27017: 'MongoDB', 9200: 'Elasticsearch',
}

@dataclass
class ScanResult:
    host: str
    port: int
    state: str
    service: Optional[str] = None
    banner: Optional[str] = None

class PortScanner:
    def __init__(self, timeout: float = 1.0, concurrency: int = 500):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.results: List[ScanResult] = []

    async def scan_port(self, host: str, port: int) -> Optional[ScanResult]:
        async with self.semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
                banner = None
                try:
                    banner_data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                    banner = banner_data.decode('utf-8', errors='ignore').strip()
                except (asyncio.TimeoutError, Exception):
                    pass
                writer.close()
                await writer.wait_closed()

                service = COMMON_PORTS.get(port)
                result = ScanResult(host=host, port=port, state='open',
                                   service=service, banner=banner)
                self.results.append(result)
                return result
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

    async def scan_host(self, host: str, ports: List[int]) -> List[ScanResult]:
        tasks = [self.scan_port(host, port) for port in ports]
        await asyncio.gather(*tasks)
        return [r for r in self.results if r.host == host]

    async def scan_range(self, cidr: str, ports: List[int]) -> List[ScanResult]:
        network = ipaddress.ip_network(cidr, strict=False)
        tasks = []
        for ip in network.hosts():
            tasks.extend([self.scan_port(str(ip), p) for p in ports])
        await asyncio.gather(*tasks)
        return self.results

def parse_ports(port_str: str) -> List[int]:
    ports = []
    for part in port_str.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def main():
    parser = argparse.ArgumentParser(description='Fast async port scanner')
    parser.add_argument('target', help='Target IP, hostname, or CIDR range')
    parser.add_argument('-p', '--ports', default='21-25,53,80,110,143,443,445,993,995,3306,3389,5432,6379,8080,8443,27017,9200',
                       help='Ports to scan (e.g. 80,443 or 1-1024)')
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='Connection timeout')
    parser.add_argument('-c', '--concurrency', type=int, default=500, help='Max concurrent connections')
    parser.add_argument('-o', '--output', choices=['text', 'json', 'csv'], default='text')
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    scanner = PortScanner(timeout=args.timeout, concurrency=args.concurrency)

    print(f'\n🔍 Scanning {args.target} ({len(ports)} ports)...\n')

    if '/' in args.target:
        results = asyncio.run(scanner.scan_range(args.target, ports))
    else:
        results = asyncio.run(scanner.scan_host(args.target, ports))

    results.sort(key=lambda r: (r.host, r.port))

    if args.output == 'json':
        print(json.dumps([asdict(r) for r in results], indent=2))
    elif args.output == 'csv':
        print('host,port,state,service,banner')
        for r in results:
            print(f'{r.host},{r.port},{r.state},{r.service or ""},{r.banner or ""}')
    else:
        if not results:
            print('No open ports found.')
        else:
            print(f'{"HOST":<20} {"PORT":<8} {"STATE":<8} {"SERVICE":<15} {"BANNER"}')
            print('-' * 70)
            for r in results:
                print(f'{r.host:<20} {r.port:<8} {r.state:<8} {r.service or "":<15} {r.banner or ""}')
        print(f'\n✅ Found {len(results)} open port(s)')

if __name__ == '__main__':
    main()