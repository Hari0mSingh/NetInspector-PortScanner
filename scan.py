import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.live import Live
from rich.layout import Layout
from rich import print as rprint
from rich.text import Text
from rich.box import DOUBLE_EDGE
from datetime import datetime
import socket
import logging
import ipaddress
from src.core.port_scanner import PortScanner
from src.core.network_discovery import NetworkDiscovery
from scanners.tcp_connect_scan import TcpConnectScan
from scanners.syn_scan import SYNScanner
from src.core.service_identifier import ServiceIdentifier
from src.core.os_fingerprinter import OSFingerprinter
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

console = Console()

def print_banner():
    """Display a stylish banner for NetInspector"""
    banner = """[bold blue]
    ███╗   ██╗███████╗████████╗██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗ ██████╗ ██████╗ 
    ████╗  ██║██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
    ██╔██╗ ██║█████╗     ██║   ██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   ██║   ██║██████╔╝
    ██║╚██╗██║██╔══╝     ██║   ██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
    ██║ ╚████║███████╗   ██║   ██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝[/bold blue]
    """
    console.print(Panel(banner, border_style="blue"))
    console.print(Panel.fit("[cyan]Port Scanner & Security Tool[/cyan]", border_style="blue"))

def create_results_table(scan_type="Basic Scan"):
    """Create a styled table for scan results"""
    table = Table(
        show_header=True,
        header_style="bold blue",
        border_style="blue",
        box=DOUBLE_EDGE,
        title=f"[bold cyan]{scan_type} Results[/bold cyan]"
    )
    table.add_column("Port", style="cyan", justify="center")
    table.add_column("Status", style="green", justify="center")
    table.add_column("Service", justify="left")
    table.add_column("Version", justify="left")
    return table

def create_os_table(os_result):
    """Create a styled table for OS detection results"""
    table = Table(
        show_header=True,
        header_style="bold yellow",
        border_style="yellow",
        box=DOUBLE_EDGE,
        title="[bold yellow]OS Detection Results[/bold yellow]"
    )
    table.add_column("Operating System", style="yellow")
    table.add_column("Confidence", style="cyan")
    table.add_row(os_result, "High")
    return table

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.argument('target')
@click.option('-p', '--ports', type=str, default="1-65535", help="Specify port range to scan (e.g., 1-1000).")
@click.option('-t', '--timeout', type=int, default=2, help="Set timeout for each connection (seconds).")
@click.option('-sT', 'scan_type', flag_value='tcp', help="Perform TCP Connect Scan.")
@click.option('-sS', 'scan_type', flag_value='syn', help="Perform SYN (half-open) Scan.")
@click.option('-sV', '--service_version', is_flag=True, help="Enable service version detection.")
@click.option('-O', '--os_detection', is_flag=True, help="Enable OS detection.")
@click.option('-o', '--output', type=str, help="Save scan results to file.")
def cli(target, ports, timeout, scan_type, service_version, os_detection, output):
    """
    NetInspector - Port Scanner Tool

    NetInspector offers a comprehensive scanning suite with various scan options like 
    TCP connect, SYN, service version detection, and OS fingerprinting. It allows scanning
    of individual hosts or entire subnets.

    TARGET can be an IP, domain, or subnet (CIDR notation).

    Examples:\n
      - Domain:\n
        scan.py scanme.nmap.org\n
        scan.py scanme.nmap.org -p 1-100 -sS\n

        with all options:\n
        python3 scan.py -sT -p 1-100 -sV -O -o scan.txt scanme.nmap.org\n

      - IP:\n
        scan.py 192.168.1.41 -p 1-100 -sT\n
        scan.py -sV 10.10.101.219:\n

        with all options:\n
        python3 scan.py -sS -p 1-2000 -sV -O -o scan_result.txt 192.168.130.147\n

      - Subnet [CIDR]:\n
        scan.py 192.168.1.0/24 -p 1-100 -sT\n
        scan.py -sV 192.168.130.0/24\n

      - Output to text file:\n
        scan.py -p 1-500 -sV -O -o scan.txt 10.10.236.66\n
    """
    print_banner()

    start_time = datetime.now()
    console.print(f"\n[cyan]Scan started at:[/cyan] {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    console.print(f"[cyan]Target:[/cyan] {target}")
    console.print(f"[cyan]Port Range:[/cyan] {ports}")

    try:
        port_range = tuple(map(int, ports.split('-')))
        if len(port_range) != 2 or port_range[0] < 1 or port_range[1] > 65535 or port_range[0] > port_range[1]:
            raise ValueError
    except ValueError:
        console.print("[red]Error:[/red] Invalid port range. Use format: 1-1000 (within 1-65535)")
        return

    if '/' in target:
        try:
            with console.status("[bold yellow]Scanning subnet...", spinner="dots"):
                network_discovery = NetworkDiscovery(subnet=target, port_range=port_range, 
                                                  timeout=timeout, scan_type=scan_type, 
                                                  service_version=service_version)
                network_discovery.scan_alive_hosts()
            return
        except ValueError:
            console.print(f"[red]Error:[/red] Invalid subnet: {target}")
            return

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        console.print(f"[red]Error:[/red] Could not resolve {target}")
        return

    if scan_type == 'syn':
        scan_instance = SYNScanner(target=target_ip, port_range=port_range, timeout=timeout)
        scan_type_name = "SYN Scan"
    elif scan_type == 'tcp':
        scan_instance = TcpConnectScan(target=target_ip, port_range=port_range, timeout=timeout)
        scan_type_name = "TCP Connect Scan"
    else:
        scan_instance = PortScanner(target=target_ip, port_range=port_range, timeout=timeout)
        scan_type_name = "Basic Scan"

    results_data = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        progress.add_task(f"[cyan]Checking if host {target_ip} is alive...", total=None)
        if not scan_instance.is_host_alive():
            console.print(f"\n[red]Host {target_ip} is not responding. Aborting scan.[/red]")
            return

        scan_task = progress.add_task(
            f"[cyan]Performing {scan_type_name}...",
            total=port_range[1] - port_range[0] + 1
        )
        open_ports = scan_instance.scan()
        progress.update(scan_task, completed=port_range[1] - port_range[0] + 1)

    if not open_ports:
        console.print(f"\n[yellow]No open ports found on {target_ip}[/yellow]")
        return

    results_table = create_results_table(scan_type_name)
    
    if service_version:
        with console.status("[cyan]Identifying services...", spinner="dots"):
            service_identifier = ServiceIdentifier(target=target_ip, timeout=timeout)
            for port in open_ports:
                service_info = service_identifier.identify_service(port)
                results_table.add_row(
                    str(port),
                    "Open",
                    service_info.get('service', 'Unknown'),
                    service_info.get('banner', 'N/A')
                )
    else:
        for port in open_ports:
            results_table.add_row(str(port), "Open", "Not Scanned", "N/A")

    console.print("\n", results_table)

    if os_detection:
        with console.status("[yellow]Detecting Operating System...", spinner="dots"):
            os_fingerprinter = OSFingerprinter(target=target_ip)
            os_result = os_fingerprinter.detect_os()
            console.print(create_os_table(os_result))

    if output:
        try:
            console.save_html(output)
            console.print(f"\n[green]Results saved to {output}[/green]")
        except Exception as e:
            console.print(f"\n[red]Error saving results: {str(e)}[/red]")

    end_time = datetime.now()
    duration = end_time - start_time
    console.print(Panel(f"""
[cyan]Scan Summary:[/cyan]
• Target: {target_ip}
• Duration: {duration}
• Open Ports: {len(open_ports)}
• Scan Type: {scan_type_name}
""", title="[bold green]Scan Complete", border_style="green"))

if __name__ == '__main__':
    cli()