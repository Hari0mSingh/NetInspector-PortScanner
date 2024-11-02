import click
from tabulate import tabulate
from colorama import Fore, Style, init
from src.core.port_scanner import PortScanner
from src.core.network_discovery import NetworkDiscovery
from scanners.tcp_connect_scan import TcpConnectScan
from scanners.syn_scan import SYNScanner
import ipaddress
import socket
from src.core.service_identifier import ServiceIdentifier
from src.core.os_fingerprinter import OSFingerprinter
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Initialize colorama
init(autoreset=True)

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.argument('target')
@click.option('-p', '--ports', type=str, default="1-65535", help="Specify the port range to scan (e.g., 1-1000). Default ports are 1-65535.")
@click.option('-t', '--timeout', type=int, default=2, help="Set the timeout for each connection attempt in seconds (default: 1).")
@click.option('-sT', 'scan_type', flag_value='tcp', help="Perform a TCP Connect Scan (default scan).")
@click.option('-sS', 'scan_type', flag_value='syn', help="Perform a SYN (half-open) Scan.")
@click.option('-sV', '--service_version', is_flag=True, help="Perform service version detection scan.")
@click.option('-O', '--os_detection', is_flag=True, help="Perform OS detection scan.")

def cli(target, ports, timeout, scan_type, service_version, os_detection):
    """
    NetInspector - port scanner.
    
    Target can be an IP, domain, or a subnet (CIDR notation supported).
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

    if '/' in target:
        try:
            click.echo(Fore.YELLOW + f"[*] Target {target} is a subnet. Starting subnet scan...")
            network_discovery = NetworkDiscovery(subnet=target, port_range=port_range, timeout=timeout, scan_type=scan_type, service_version=service_version)
            network_discovery.scan_alive_hosts()
            return
        except ValueError:
            click.echo(Fore.RED + f"[-] Error: {target} is not a valid subnet.")
            return
    else:
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            click.echo(Fore.RED + f"[-] Unable to resolve target {target}.")
            return

        click.echo(Fore.YELLOW + f"[*] Target {target_ip} host ...")

        if scan_type == 'syn':
            scan_instance = SYNScanner(target=target_ip, port_range=port_range, timeout=timeout)
        elif scan_type == 'tcp':
            scan_instance = TcpConnectScan(target=target_ip, port_range=port_range, timeout=timeout)
        else:
            scan_instance = PortScanner(target=target_ip, port_range=port_range, timeout=timeout)

        if scan_instance.is_host_alive():
            open_ports = scan_instance.scan()
            if open_ports:
                click.echo(Fore.GREEN + f"\n[+] Open ports found on {target_ip}:")
                table_data = [[port, "Open"] for port in open_ports]
                click.echo(tabulate(table_data, headers=[Fore.BLUE + "Port", Fore.BLUE + "Status"], tablefmt="fancy_grid"))

                if service_version:
                    service_identifier = ServiceIdentifier(target=target_ip, timeout=timeout)
                    for port in open_ports:
                        service_info = service_identifier.identify_service(port)
                        click.echo(Fore.GREEN + f"Port: {port}, Service: {service_info['service']}, Banner: {service_info['banner']}")
                
                if os_detection:
                    os_fingerprinter = OSFingerprinter(target=target_ip, timeout=timeout)
                    os_result = os_fingerprinter.get_ttl_based_os()
                    if "error" not in os_result:
                        click.echo(Fore.CYAN + f"[+] OS Detection result for {target_ip}: TTL = {os_result['ttl']}, OS = {os_result['os']}")
                    else:
                        click.echo(Fore.RED + f"[-] OS Detection Error: {os_result['error']}")
            else:
                click.echo(Fore.RED + f"[-] No open ports found on {target_ip}.")
        else:
            click.echo(Fore.RED + f"[-] Host {target_ip} is not alive. Aborting scan.")

if __name__ == '__main__':
    cli()
