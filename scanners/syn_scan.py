from scapy.all import sr1, IP, TCP
import random
from src.core.port_scanner import PortScanner 

class SYNScanner:
    def __init__(self, target, port_range=None, timeout=1):
        self.target = target
        self.port_range = port_range if port_range else (1, 65535)
        self.timeout = timeout
        self.scanner = PortScanner(target, port_range, timeout)
        print(f"[*] Performing SYN scan on target {self.target}")

    def is_host_alive(self):
        return self.scanner.is_host_alive() 

    def scan(self):
        open_ports = []

        if not self.is_host_alive():
            return open_ports

        print(f"[+] Host {self.target} is alive, starting SYN Scan...")

        for port in range(self.port_range[0], self.port_range[1] + 1):
            if self.syn_scan(port):
                print(f"[+] Port {port} is open.")
                open_ports.append(port)

        print(f"[*] SYN Scan completed on target {self.target}.")
        return open_ports

    def syn_scan(self, port):
        src_port = random.randint(1, 65535)
        syn_packet = IP(dst=self.target) / TCP(dport=port, sport=src_port, flags='S')
        response = sr1(syn_packet, timeout=self.timeout, verbose=False)

        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:  # SYN-ACK
            rst_packet = IP(dst=self.target) / TCP(dport=port, sport=src_port, flags='R')
            sr1(rst_packet, timeout=self.timeout, verbose=False)
            return True
        return False
