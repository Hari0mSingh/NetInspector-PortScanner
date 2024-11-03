from scapy.all import sr1, IP, TCP
import random
from src.core.port_scanner import PortScanner
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

class SYNScanner:
    def __init__(self, target, port_range=None, timeout=1, max_threads=100):
        """
        Initialize the SYN scanner with multithreading.

        Args:
            target (str): The target IP or domain to scan.
            port_range (tuple): A tuple specifying the range of ports to scan (default: 1-65535).
            timeout (int): Timeout in seconds for each SYN packet response (default: 1).
            max_threads (int): Maximum number of threads to use for scanning (default: 100).
        """
        self.target = target
        self.port_range = port_range if port_range else (1, 65535)
        self.timeout = timeout
        self.max_threads = max_threads
        self.scanner = PortScanner(target, port_range, timeout)
        self.lock = threading.Lock()  
        print(f"[*] Performing SYN scan on target {self.target} with up to {self.max_threads} threads")

    def is_host_alive(self):
        """
        Check if the target host is alive.
        
        Returns:
            bool: True if the host is alive, False otherwise.
        """
        return self.scanner.is_host_alive()

    def scan(self):
        """
        Perform the SYN scan on the specified port range using multithreading.

        Returns:
            list: A list of open ports.
        """
        open_ports = []

        if not self.is_host_alive():
            return open_ports

        print(f"[+] Host {self.target} is alive, starting SYN Scan...")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {executor.submit(self.syn_scan, port): port for port in range(self.port_range[0], self.port_range[1] + 1)}

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        with self.lock:
                            print(f"[+] Port {port} is open.")
                            open_ports.append(port)
                except Exception as e:
                    print(f"[-] Error scanning port {port}: {e}")

        print(f"[*] SYN Scan completed on target {self.target}.")
        return open_ports

    def syn_scan(self, port):
        """
        Send a SYN packet to a specified port and check if it's open.

        Args:
            port (int): The port to scan.

        Returns:
            bool: True if the port is open, False otherwise.
        """
        src_port = random.randint(1, 65535)
        syn_packet = IP(dst=self.target) / TCP(dport=port, sport=src_port, flags='S')
        response = sr1(syn_packet, timeout=self.timeout, verbose=False)

        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            rst_packet = IP(dst=self.target) / TCP(dport=port, sport=src_port, flags='R')
            sr1(rst_packet, timeout=self.timeout, verbose=False)
            return True
        return False
