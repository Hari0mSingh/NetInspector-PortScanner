import click
from tabulate import tabulate
from colorama import Fore, Style, init
from src.core.port_scanner import PortScanner
from src.core.network_discovery import NetworkDiscovery
from scanners.tcp_connect_scan import TcpConnectScan
from scanners.syn_scan import SYNScanner
import ipaddress
import socket

# Initialize colorama
init(autoreset=True)

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.argument('target')

@click.option('-p', '--ports', type=str, default="1-65535", help="Specify the port range to scan (e.g., 1-1000). Default ports are 1-65535.")
@click.option('-t', '--timeout', type=int, default=2, help="Set the timeout for each connection attempt in seconds (default: 1).")
@click.option('-sT', 'scan_type', flag_value='tcp', help="Perform a TCP Connect Scan (default scan).")
@click.option('-sS', 'scan_type', flag_value='syn', help="Perform a SYN (half-open) Scan.")
def cli(target, ports, timeout, scan_type):
    """
    \b
    NetInspector - port scanner.
    
    Target can be an IP, domain, or a subnet (CIDR notation supported).

    Available scan types:\n
    \b
      - TCP Connect Scan (default): Full TCP connection on each port.\n
      - SYN Scan (-sS): Stealthy SYN packets only (no full connection).\n
    
    \b
    Examples: 

    Scan first 1000 ports of an IP:\n
      python main.py 192.168.1.1 --ports 1-1000

    Scan a subnet and alive hosts:\n
      python main.py 192.168.1.0/24
    """

    click.echo(Fore.CYAN + "============================================================")
    click.echo(Fore.GREEN + "                  NetInspector - Port Scanner              ")
    click.echo(Fore.CYAN + "============================================================")

    try:
        port_range = tuple(map(int, ports.split('-')))
        if len(port_range) != 2 or port_range[0] < 1 or port_range[1] > 65535 or port_range[0] > port_range[1]:
            raise ValueError
    except ValueError:
        click.echo(Fore.RED + "Error: Invalid port range format. Use format: 1-1000 (within 1-65535).")
        return

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        target_ip = target 

    if '/' in target_ip:
        try:
            ipaddress.ip_network(target_ip, strict=False)
            click.echo(Fore.YELLOW + f"[*] Target {target_ip} is a subnet. Starting subnet scan...")
            network_discovery = NetworkDiscovery(subnet=target_ip, port_range=port_range, timeout=timeout, scan_type=scan_type)
            network_discovery.scan_alive_hosts()
            return
        except ValueError:
            click.echo(Fore.RED + f"[-] Error: {target_ip} is not a valid subnet.")
            return
    else:
        try:
            ipaddress.ip_address(target_ip)
        except ValueError:
            click.echo(Fore.RED + f"[-] Error: {target_ip} is not a valid IP address.")
            return

        click.echo(Fore.YELLOW + f"[*] Target {target_ip} host ...")

        if scan_type == 'syn':
            scan_instance = SYNScanner(target=target_ip, port_range=port_range, timeout=timeout)
            open_ports = scan_instance.scan()
        elif scan_type == 'tcp':
            scan_instance = TcpConnectScan(target=target_ip, port_range=port_range, timeout=timeout)
            open_ports = scan_instance.scan()
        else:
            scanner = PortScanner(target=target_ip, port_range=port_range, timeout=timeout)
            if scanner.is_host_alive():
                open_ports = scanner.scan()
            else:
                click.echo(Fore.RED + f"[-] Host {target_ip} is not alive. Aborting scan.")
                return

        if open_ports:
            click.echo(Fore.GREEN + f"\n[+] Open ports found on {target_ip}:")
            table_data = [[port, "Open"] for port in open_ports]
            click.echo(tabulate(table_data, headers=[Fore.BLUE + "Port", Fore.BLUE + "Status"], tablefmt="fancy_grid"))
        else:
            click.echo(Fore.RED + f"[-] No open ports found on {target_ip}.")

if __name__ == '__main__':
    cli()
