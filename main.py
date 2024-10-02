# main.py

import click
from tabulate import tabulate
from colorama import Fore, Style, init
from src.core.port_scanner import PortScanner

# Initialize colorama
init(autoreset=True)

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.argument('target')
@click.option('-p', '--ports', type=str, default=None, help="Specify a port range to scan (e.g., 1-1000). Default scans all ports (1-65535).")
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
    """

    # banner that will display on screen
    click.echo(Fore.CYAN + "=====================================")
    click.echo(Fore.GREEN + "      NetInspector - port scanner    ")
    click.echo(Fore.CYAN + "=====================================")

    # Parse the port range if specified
    if ports:
        try:
            port_range = tuple(map(int, ports.split('-')))
            # Validated port range
            if len(port_range) != 2 or port_range[0] < 1 or port_range[1] > 65535 or port_range[0] > port_range[1]:
                raise ValueError
            click.echo(Fore.YELLOW + f"Scanning {target} on ports {port_range[0]} to {port_range[1]}")
        except ValueError:
            click.echo(Fore.RED + "Error: Invalid port range format. Use format: 1-1000 (within 1-65535).")
            return
    else:
        port_range = (1, 65535)
        click.echo(Fore.YELLOW + f"Scanning {target} on all ports (1-65535)")

    # port scanner object
    scanner = PortScanner(target=target, port_range=port_range, timeout=timeout)

    # Check if the host is alive before scanning
    if not scanner.is_host_alive():
        click.echo(Fore.RED + f"Host {target} is not alive! or maybe not reachable.")
        return
    
    # Start the scan
    open_ports = scanner.scan()

    if open_ports:
        # Display results in a table format
        click.echo(Fore.GREEN + f"\nOpen ports found on {target}:")
        table_data = [[port, "Open"] for port in open_ports]
        click.echo(tabulate(table_data, headers=[Fore.BLUE + "Port", Fore.BLUE + "Status"], tablefmt="fancy_grid"))
    else:
        click.echo(Fore.RED + f"No open ports found on {target}.")

if __name__ == '__main__':
    cli()
