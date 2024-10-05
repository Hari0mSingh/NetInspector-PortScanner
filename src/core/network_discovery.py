import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.core.port_scanner import PortScanner
from tabulate import tabulate
from colorama import Fore
import sys
import os
from contextlib import contextmanager

@contextmanager
def suppress_stderr():
    """Context manager to suppress stderr output (such as warnings)."""
    with open(os.devnull, 'w') as devnull:
        old_stderr = sys.stderr
        sys.stderr = devnull
        try:
            yield
        finally:
            sys.stderr = old_stderr

class NetworkDiscovery:
    def __init__(self, subnet, port_range=None, timeout=1):
        self.subnet = subnet
        self.port_range = port_range if port_range else (1, 65535)
        self.timeout = timeout

    def check_host_alive(self, ip_str):
        """Check if a single host is alive."""
        scanner = PortScanner(target=ip_str, port_range=self.port_range, timeout=self.timeout)
        with suppress_stderr(): 
            if scanner.is_host_alive():
                return ip_str
        return None

    def scan_subnet(self):
        """Scan the subnet for alive hosts."""
        alive_hosts = []
        subnet_network = ipaddress.ip_network(self.subnet, strict=False)

        print(f"[*] Scanning the {self.subnet} subnet for alive Hosts...")

        # Increase max_workers to speed up the scan
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {executor.submit(self.check_host_alive, str(ip)): str(ip) for ip in subnet_network.hosts()}

            for future in as_completed(future_to_ip):
                result = future.result()
                if result:
                    print(f"Host {result} is alive.")
                    alive_hosts.append(result)

        return alive_hosts

    def scan_alive_hosts(self):
        """Scan alive hosts in the subnet for open ports."""
        alive_hosts = self.scan_subnet()

        if not alive_hosts:
            print(Fore.RED + "No alive hosts found in the subnet.")
            return

        print(Fore.YELLOW + f"\nScanning {len(alive_hosts)} alive hosts for open ports...")

        # Prepare data for tabulation
        scan_results = []

        # Scan each alive host for open ports
        for host in alive_hosts:
            print(Fore.CYAN + f"\nScanning host {host}...")
            scanner = PortScanner(target=host, port_range=self.port_range, timeout=self.timeout)
            open_ports = scanner.scan()

            if open_ports:
                scan_results.append([host, Fore.GREEN + ", ".join(map(str, open_ports))])  # Collecting results
                print(Fore.GREEN + f"Host {host} has the following open ports: {open_ports}")
            else:
                scan_results.append([host, Fore.RED + "No open ports found"])  # Collecting results
                print(Fore.RED + f"No open ports found on {host}.")

        # Displaying results in a tabular format
        print(Fore.YELLOW + "\nScan Results:")
        print(tabulate(scan_results, headers=[Fore.BLUE + "Host", Fore.BLUE + "Open Ports"], tablefmt="fancy_grid"))
