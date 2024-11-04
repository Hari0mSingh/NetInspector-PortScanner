import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.core.port_scanner import PortScanner
from tabulate import tabulate
from colorama import Fore
import sys
import os
from contextlib import contextmanager
from scanners.tcp_connect_scan import TcpConnectScan
from scanners.syn_scan import SYNScanner
from src.core.service_identifier import ServiceIdentifier

@contextmanager
def suppress_stderr():
    with open(os.devnull, 'w') as devnull:
        old_stderr = sys.stderr
        sys.stderr = devnull
        try:
            yield
        finally:
            sys.stderr = old_stderr

class NetworkDiscovery:
    def __init__(self, subnet, port_range=None, timeout=1, scan_type=None, service_version=False):
        self.subnet = subnet
        self.port_range = port_range if port_range else (1, 65535)
        self.timeout = timeout
        self.scan_type = scan_type
        self.service_version = service_version

    def check_host_alive(self, ip_str):
        scanner = PortScanner(target=ip_str, port_range=self.port_range, timeout=self.timeout)
        with suppress_stderr(): 
            if scanner.is_host_alive():
                return ip_str
        return None

    def scan_subnet(self):
        alive_hosts = []
        subnet_network = ipaddress.ip_network(self.subnet, strict=False)

        print(f"[*] Scanning the {self.subnet} subnet for alive hosts...")

        with ThreadPoolExecutor(max_workers=100) as executor:
            future_to_ip = {executor.submit(self.check_host_alive, str(ip)): str(ip) for ip in subnet_network.hosts()}

            for future in as_completed(future_to_ip):
                result = future.result()
                if result:
                    print(f"[+] Host {result} is alive.")
                    alive_hosts.append(result)
        return alive_hosts

    def scan_alive_hosts(self):
        alive_hosts = self.scan_subnet()

        if not alive_hosts:
            print(Fore.RED + "[-] No alive hosts found in the subnet.")
            return

        all_results = {}
        for host in alive_hosts:
            scanner = None
            if self.scan_type == 'syn':
                scanner = SYNScanner(target=host, port_range=self.port_range, timeout=self.timeout)
            elif self.scan_type == 'tcp':
                scanner = TcpConnectScan(target=host, port_range=self.port_range, timeout=self.timeout)
            else:
                scanner = PortScanner(target=host, port_range=self.port_range, timeout=self.timeout)

            open_ports = scanner.scan()

            # Group open ports by host
            all_results[host] = open_ports

        # Prepare data for tabulation
        table_data = []
        for host, ports in all_results.items():
            for port in ports:
                table_data.append([host, port])

        table_headers = [Fore.BLUE + "Host", "Port"]
        table_output = tabulate(table_data, headers=table_headers, tablefmt="fancy_grid")
        print(table_output)
