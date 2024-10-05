import click
from tabulate import tabulate
from colorama import Fore, Style, init
from src.core.port_scanner import PortScanner
from src.core.network_discovery import NetworkDiscovery
import ipaddress
import socket

# Initialize colorama
init(autoreset=True)

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.argument('target')
@click.option('-p', '--ports', type=str, default="1-1000", help="Specify a port range to scan (e.g., 1-1000). Default scans ports 1-1000.")
@click.option('-t', '--timeout', type=int, default=2, help="Set the timeout for each connection attempt, in seconds (default: 2).")
def cli(target, ports, timeout):
    """
    \b
    NetInspector - Port Scanner.
    \b
    Examples:
    
    Scan the first 1000 ports of an IP:
      python main.py 192.168.1.1 --ports 1-1000
    
    Scan all ports of a domain:
      python main.py example.com
    
    Set a custom timeout of 5 seconds:
      python main.py 192.168.1.1 --timeout 5
    
    Scan a subnet:
      python main.py 192.168.1.0/24 --ports 1-100
    """

    click.echo(Fore.CYAN + "===================================================")
    click.echo(Fore.GREEN + "             NetInspector - port scanner          ")
    click.echo(Fore.CYAN + "===================================================")

    # Parse the port range if specified
    if ports:
        try:
            port_range = tuple(map(int, ports.split('-')))
            if len(port_range) != 2 or port_range[0] < 1 or port_range[1] > 65535 or port_range[0] > port_range[1]:
                raise ValueError
            click.echo(Fore.YELLOW + f"Scanning {target} on ports {port_range[0]} to {port_range[1]}")
        except ValueError:
            click.echo(Fore.RED + "Error: Invalid port range format. Use format: 1-1000 (within 1-65535).")
            return
    else:
        port_range = (1, 1000)
        click.echo(Fore.YELLOW + f"Scanning {target} on ports 1-1000")

    try:
        try:
            target_ip = socket.gethostbyname(target)
            click.echo(Fore.YELLOW + f"Resolved domain {target} to IP {target_ip}.")
        except socket.gaierror:
            target_ip = target 

        if '/' in target_ip:
            try:
                ipaddress.ip_network(target_ip, strict=False)
                click.echo(Fore.YELLOW + f"Target {target_ip} is a subnet. Starting subnet scan...")
                
                network_discovery = NetworkDiscovery(subnet=target_ip, port_range=port_range, timeout=timeout)
                network_discovery.scan_alive_hosts()
                return

            except ValueError:
                click.echo(Fore.RED + f"Error: {target_ip} is not a valid subnet.")
                return
        
        else:
            ipaddress.ip_address(target_ip)
            click.echo(Fore.YELLOW + f"Target {target_ip} is a single host. Starting single host scan...")

            scanner = PortScanner(target=target_ip, port_range=port_range, timeout=timeout)

            if not scanner.is_host_alive():
                click.echo(Fore.RED + f"Host {target_ip} is not alive or unreachable.")
                return

            open_ports = scanner.scan()

            if open_ports:
                click.echo(Fore.GREEN + f"\nOpen ports found on {target_ip}:")
                table_data = [[port, "Open"] for port in open_ports]
                click.echo(tabulate(table_data, headers=[Fore.BLUE + "Port", Fore.BLUE + "Status"], tablefmt="fancy_grid"))
            else:
                click.echo(Fore.RED + f"No open ports found on {target_ip}.")
    
    except ValueError:
        click.echo(Fore.RED + f"Error: {target} is not a valid IP address, subnet, or domain.")
        return

if __name__ == '__main__':
    cli()
