import socket
import concurrent.futures
from scapy.all import ICMP, IP, sr1

class PortScanner:
    def __init__(self, target, port_range=None, timeout=1):
        self.target = target
        self.port_range = port_range if port_range else (1, 65535)
        self.timeout = timeout
    
    
    def is_host_alive(self):
       
        # Try connecting to common ports to see if the host is alive
        if self.tcp_connect_check_common_ports():
            return True
      
        return False

    def tcp_connect_check_common_ports(self):
        """Check TCP connection on common ports."""
        common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 443]
        for port in common_ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    print(f"Host {self.target} is alive (common port {port} is open).")
                    return True
        return False

    def tcp_connect_scan(self, port):
        """Perform a TCP Connect scan on a specific port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                return port, result == 0
        except Exception:
            return port, False

    def scan(self):
        """Scan the specified range of ports."""
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(self.tcp_connect_scan, port) for port in range(self.port_range[0], self.port_range[1] + 1)]
            for future in concurrent.futures.as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
                    print(f"Port {port} is open")

        return open_ports
