import socket

class ServiceIdentifier:
    COMMON_SERVICES = {
        20: "FTP-Data",
        21: "FTP-Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        37: "Time Protocol",
        43: "WHOIS",
        53: "DNS",
        67: "DHCP Server",
        68: "DHCP Client",
        69: "TFTP",
        70: "Gopher",
        79: "Finger",
        80: "HTTP",
        88: "Kerberos",
        109: "POP2",
        110: "POP3",
        115: "SFTP",
        118: "SQL Services",
        119: "NNTP",
        123: "NTP",
        135: "Microsoft RPC",
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram Service",
        139: "NetBIOS Session Service",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP Trap",
        179: "BGP",
        194: "IRC",
        389: "LDAP",
        443: "HTTPS",
        445: "Microsoft-DS (SMB)",
        464: "Kerberos Password Change",
        465: "SMTPS",
        514: "Syslog",
        515: "LPD/LPR",
        520: "RIP",
        521: "RIPng (IPv6)",
        543: "Kerberos Login",
        544: "Kerberos Shell",
        547: "DHCPv6 Server",
        548: "AFP",
        554: "RTSP",
        587: "SMTP (Submission)",
        631: "IPP",
        636: "LDAPS",
        873: "rsync",
        989: "FTPS Data",
        990: "FTPS Control",
        993: "IMAPS",
        995: "POP3S",
        1080: "SOCKS Proxy",
        1194: "OpenVPN",
        1433: "Microsoft SQL Server",
        1434: "Microsoft SQL Monitor",
        1521: "Oracle",
        1723: "PPTP",
        1812: "RADIUS Authentication",
        1813: "RADIUS Accounting",
        2049: "NFS",
        2082: "cPanel",
        2083: "cPanel SSL",
        2086: "WHM",
        2087: "WHM SSL",
        2222: "DirectAdmin",
        3128: "Squid Proxy",
        3306: "MySQL",
        3389: "RDP",
        3690: "SVN",
        4333: "mSQL",
        4444: "Metasploit",
        5060: "SIP",
        5061: "SIP-TLS",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        6665: "IRC",
        6666: "IRC",
        6667: "IRC",
        6668: "IRC",
        6669: "IRC",
        8000: "Alternative HTTP",
        8080: "HTTP Proxy",
        8443: "Alternative HTTPS",
        9000: "PHP-FPM",
        9090: "WebSphere Admin",
        9200: "Elasticsearch",
        9418: "Git",
        10000: "Webmin",
        11211: "Memcached",
        27017: "MongoDB",
        27018: "MongoDB Sharded",
        27019: "MongoDB Config Server",
        50000: "SAP",
        54321: "PostgreSQL Default"
    }
    def __init__(self, target, timeout=1):
        self.target = target
        self.timeout = timeout

    def identify_service(self, port):
        service = self.COMMON_SERVICES.get(port, "Unknown")
        banner = self.grab_banner(port)
        return {"port": port, "service": service, "banner": banner}
        
    def grab_banner(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((self.target, port))
                sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
                return sock.recv(1024).decode().strip()
        except Exception as e:
            return f"Banner grabbing failed: {e}"
