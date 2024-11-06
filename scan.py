import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.live import Live
from rich.layout import Layout
from rich import print as rprint
from rich.text import Text
from rich.box import DOUBLE_EDGE, ROUNDED
from rich.prompt import Confirm
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

console = Console(record=True)

def print_banner():
    banner = """[bold blue]
    ███╗   ██╗███████╗████████╗██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗ ██████╗ ██████╗ 
    ████╗  ██║██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
    ██╔██╗ ██║█████╗     ██║   ██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   ██║   ██║██████╔╝
    ██║╚██╗██║██╔══╝     ██║   ██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
    ██║ ╚████║███████╗   ██║   ██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝[/bold blue]
    """
    version_info = "[cyan]v1.0.0[/cyan]"
    console.print(Panel(banner, border_style="blue", box=ROUNDED))
    console.print(Panel.fit(
        "[cyan]Port Scanner [/cyan]\n" + version_info,
        border_style="blue",
        box=ROUNDED
    ))

def create_results_table(scan_type="Basic Scan"):
    table = Table(
        show_header=True,
        header_style="bold blue",
        border_style="blue",
        box=ROUNDED,
        title=f"[bold cyan]{scan_type} Results[/bold cyan]",
        title_justify="center",
        expand=True
    )
    table.add_column("Port", style="cyan", justify="center")
    table.add_column("Status", style="green", justify="center")
    table.add_column("Service", justify="left", style="yellow")
    table.add_column("Version", justify="left", style="magenta")
    return table

def create_os_table(os_result):
    table = Table(
        show_header=True,
        header_style="bold yellow",
        border_style="yellow",
        box=ROUNDED,
        title="[bold yellow]OS Detection Results[/bold yellow]",
        expand=True
    )
    table.add_column("Operating System", style="yellow")
    table.add_column("Confidence", style="cyan")
    table.add_row(os_result, "High")
    return table

def save_results_to_text(filename, target_ip, scan_type_name, open_ports, service_info=None, os_result=None, start_time=None, end_time=None):
    """
    Save scan results to a formatted text file
    """
    with open(filename, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("NETWORK INSPECTOR SCAN RESULTS\n")
        f.write("=" * 80 + "\n\n")

        f.write("SCAN INFORMATION\n")
        f.write("-" * 80 + "\n")
        f.write(f"Target IP: {target_ip}\n")
        f.write(f"Scan Type: {scan_type_name}\n")
        if start_time and end_time:
            f.write(f"Start Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"End Time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {end_time - start_time}\n")
        f.write("\n")

        f.write("PORT SCAN RESULTS\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'PORT':<10}{'STATUS':<15}{'SERVICE':<20}{'VERSION':<35}\n")
        f.write("-" * 80 + "\n")
        
        if service_info:
            for port in open_ports:
                service = service_info.get(port, {})
                f.write(f"{str(port):<10}{'Open':<15}{service.get('service', 'Unknown'):<20}{service.get('banner', 'N/A'):<35}\n")
        else:
            for port in open_ports:
                f.write(f"{str(port):<10}{'Open':<15}{'Not Scanned':<20}{'N/A':<35}\n")
        f.write("\n")

        if os_result:
            f.write("OPERATING SYSTEM DETECTION\n")
            f.write("-" * 80 + "\n")
            f.write(f"Detected OS: {os_result}\n")
            f.write(f"Confidence: High\n")
            f.write("\n")

        f.write("=" * 80 + "\n")
        f.write("End of Scan Report\n")
        f.write("=" * 80 + "\n")

def validate_port_range(ctx, param, value):
    try:
        start, end = map(int, value.split('-'))
        if not (1 <= start <= end <= 65535):
            raise ValueError
        return (start, end)
    except ValueError:
        raise click.BadParameter('Port range must be in format START-END (1-65535)')

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.argument('target')
@click.option('-p', '--ports',
              type=str,
              default="1-65535",
              help="Specify port range to scan (e.g., 1-1000).",
              callback=validate_port_range)
@click.option('-t', '--timeout',
              type=click.IntRange(1, 30),
              default=2,
              help="Set timeout for each connection (seconds).")
@click.option('-sT', 'scan_type',
              flag_value='tcp',
              help="Perform TCP Connect Scan.")
@click.option('-sS', 'scan_type',
              flag_value='syn',
              help="Perform SYN (half-open) Scan.")
@click.option('-sV', '--service_version',
              is_flag=True,
              help="Enable service version detection.")
@click.option('-O', '--os_detection',
              is_flag=True,
              help="Enable OS detection.")
@click.option('-o', '--output',
              type=click.Path(dir_okay=False),
              help="Save scan results to file (use .html extension for HTML output).")
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
    
    console.print(Panel(
        f"""[cyan]Scan Configuration[/cyan]
• Target: {target}
• Port Range: {ports[0]}-{ports[1]}
• Timeout: {timeout}s
• Scan Type: {scan_type or 'Basic'}
• Service Detection: {'Enabled' if service_version else 'Disabled'}
• OS Detection: {'Enabled' if os_detection else 'Disabled'}""",
        title="[bold green]Scan Started",
        border_style="green",
        box=ROUNDED
    ))

    if '/' in target:
        try:
            with console.status("[bold yellow]Scanning subnet...", spinner="dots"):
                network_discovery = NetworkDiscovery(subnet=target, port_range=ports, 
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
        scan_instance = SYNScanner(target=target_ip, port_range=ports, timeout=timeout)
        scan_type_name = "SYN Scan"
    elif scan_type == 'tcp':
        scan_instance = TcpConnectScan(target=target_ip, port_range=ports, timeout=timeout)
        scan_type_name = "TCP Connect Scan"
    else:
        scan_instance = PortScanner(target=target_ip, port_range=ports, timeout=timeout)
        scan_type_name = "Basic Scan"

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        progress.add_task(f"[cyan]Host {target_ip} is alive ?", total=None)
        if not scan_instance.is_host_alive():
            console.print(f"\n[red]Host {target_ip} is not responding. Aborting scan.[/red]")
            return

        scan_task = progress.add_task(
            f"[cyan]Performing {scan_type_name}...",
            total=ports[1] - ports[0] + 1
        )
        open_ports = scan_instance.scan()
        progress.update(scan_task, completed=ports[1] - ports[0] + 1)

    if not open_ports:
        console.print(f"\n[yellow]No open ports found on {target_ip}[/yellow]")
        return

    results_table = create_results_table(scan_type_name)
    service_info = {}
    
    if service_version:
        with console.status("[cyan]Identifying services...", spinner="dots"):
            service_identifier = ServiceIdentifier(target=target_ip, timeout=timeout)
            for port in open_ports:
                service_info[port] = service_identifier.identify_service(port)
                results_table.add_row(
                    str(port),
                    "Open",
                    service_info[port].get('service', 'Unknown'),
                    service_info[port].get('banner', 'N/A')
                )
    else:
        for port in open_ports:
            results_table.add_row(str(port), "Open", "Not Scanned", "N/A")

    console.print("\n", results_table)

    os_result = None
    if os_detection:
        with console.status("[yellow]Detecting Operating System...", spinner="dots"):
            os_fingerprinter = OSFingerprinter(target=target_ip)
            os_result = os_fingerprinter.detect_os()
            console.print(create_os_table(os_result))

    if output:
        try:
            if output.endswith('.html'):
                console.save_html(output)
            else:
                save_results_to_text(
                    filename=output,
                    target_ip=target_ip,
                    scan_type_name=scan_type_name,
                    open_ports=open_ports,
                    service_info=service_info if service_version else None,
                    os_result=os_result if os_detection else None,
                    start_time=start_time,
                    end_time=datetime.now()
                )
            console.print(f"\n[green]Results saved to {output}[/green]")
        except Exception as e:
            console.print(f"\n[red]Error saving results: {str(e)}[/red]")

    end_time = datetime.now()
    duration = end_time - start_time
    console.print(Panel(
        f"""[cyan]Scan Summary[/cyan]
• Target: {target_ip}
• Duration: {duration}
• Open Ports: {len(open_ports)}
• Scan Type: {scan_type_name}
• Scan Completed: {end_time.strftime('%Y-%m-%d %H:%M:%S')}""",
        title="[bold green]Scan Complete",
        border_style="green",
        box=ROUNDED
    ))

if __name__ == '__main__':
    cli()