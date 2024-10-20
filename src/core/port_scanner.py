import socket
import concurrent.futures
from scapy.all import ICMP, IP, sr1, conf


class PortScanner:
    def __init__(self, target, port_range=None, timeout=1):
        self.target = target
        self.port_range = port_range if port_range else (1, 65535)
        self.timeout = timeout

    def is_host_alive(self):
        """Check if the host is alive using TCP and ICMP."""

        if self.tcp_connect_check_common_ports():
            print(f"[+] Host {self.target} is alive (TCP check).")
            return True

        if self.icmp_ping_check():
            print(f"[+] Host {self.target} is alive (ICMP ping check).")
            return True

        print(f"[-] Host {self.target} is not alive or unreachable.")
        return False

    def icmp_ping_check(self):
        """Perform an ICMP ping check."""
        try:
            conf.verb = 0  # Suppress Scapy output
            packet = IP(dst=self.target) / ICMP()
            response = sr1(packet, timeout=self.timeout, verbose=False)
            if response and response.haslayer(ICMP):
                return True
        except Exception as e:
            print(f"[-] ICMP ping check failed: {e}")
        return False

    def tcp_connect_check_common_ports(self):
        """Check TCP connection on common ports."""
        common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389]
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((self.target, port))
                    if result == 0:  # If the port is open
                        return True
            except socket.error as e:
                print(f"[-] Error checking TCP port {port}: {e}")
        return False

    def tcp_connect_scan(self, port):
        """Perform a TCP Connect scan on a specific port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                return port, result == 0
        except Exception as e:
            print(f"[-] Error scanning port {port} on {self.target}: {e}")
            return port, False

    def scan(self):
        """Scan the specified range of ports."""
        open_ports = []
        print(f"[*] Starting scan on {self.target} for ports {self.port_range[0]}-{self.port_range[1]}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=150) as executor:
            futures = [executor.submit(self.tcp_connect_scan, port) for port in range(self.port_range[0], self.port_range[1] + 1)]
            for future in concurrent.futures.as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
                    print(f"[+] Port {port} is open")

        if open_ports:
            print(f"[+] Scan completed: Open ports on {self.target}: {open_ports}")
        else:
            print(f"[-] No open ports found on {self.target}.")

        return open_ports
