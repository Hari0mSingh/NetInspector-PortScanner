import socket
from concurrent.futures import ThreadPoolExecutor
from src.core.port_scanner import PortScanner 


class TcpConnectScan:
    def __init__(self, target, port_range=None, timeout=1):
        self.target = target
        self.port_range = port_range if port_range else (1, 65535)
        self.timeout = timeout
        self.scanner = PortScanner(target, port_range, timeout)
        print(f"[*] Performing TCP Connect scan on target {self.target}")

    def is_host_alive(self):
        return self.scanner.is_host_alive() 

    def tcp_connect_scan(self, port):
        """Perform a TCP Connect scan on a single port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            return port, result == 0 

    def scan(self):
        """Perform a TCP Connect Scan on the specified range of ports."""
        open_ports = []

        if not self.is_host_alive():
            print(f"[-] Host {self.target} is not alive or unreachable.")
            return open_ports  

        print(f"[+] Host {self.target} is alive, starting TCP Connect Scan...")
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self.tcp_connect_scan, port): port for port in range(self.port_range[0], self.port_range[1] + 1)}
            for future in futures:
                port, is_open = future.result()
                if is_open:
                    print(f"[+] Port {port} is open.")
                    open_ports.append(port)

        print(f"[*] TCP Connect Scan completed on target {self.target}.")
        return open_ports
