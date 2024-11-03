from scapy.all import IP, IPv6, ICMP, ICMPv6EchoRequest, sr1
import ipaddress

class OSFingerprinter:
    TTL_OS_MAPPING = {
        range(32, 65): "Linux/Unix",
        range(65, 129): "Windows",
        range(129, 256): "Cisco/Networking Devices"
    }

    def __init__(self, target, timeout=1):
        self.target = target
        self.timeout = timeout
        self.ip_version = self._detect_ip_version()

    def _detect_ip_version(self):
        try:
            ipaddress.IPv4Address(self.target)
            return 4
        except ipaddress.AddressValueError:
            try:
                ipaddress.IPv6Address(self.target)
                return 6
            except ipaddress.AddressValueError:
                raise ValueError("Invalid IP address")

    def detect_os(self):
        """Perform OS detection based on TTL."""
        try:
            if self.ip_version == 4:
                icmp_packet = IP(dst=self.target) / ICMP()
            else:
                icmp_packet = IPv6(dst=self.target) / ICMPv6EchoRequest()
            
            response = sr1(icmp_packet, timeout=self.timeout, verbose=False)
            if response:
                ttl = response.ttl
                os_type = self._map_ttl_to_os(ttl)
                return os_type
            else:
                return {"error": "No response received for OS fingerprinting."}
        except Exception as e:
            return {"error": f"OS fingerprinting failed: {e}"}

    def _map_ttl_to_os(self, ttl):
        for ttl_range, os_type in self.TTL_OS_MAPPING.items():
            if ttl in ttl_range:
                return os_type
        return "Unknown OS"
