#!/usr/bin/env python3
"""
agera.py - Agera: Professional DNS & WHOIS Enumeration Tool

A modular, secure, and visually appealing enumeration tool for authorized
penetration testing. Performs DNS record scanning and WHOIS lookups with
rich-colored output and structured reporting.

Author: Security Engineer
License: For authorized use only.
"""

import sys
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

import typer
import dns.resolver
import dns.exception
import whois
from pyfiglet import Figlet
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

# Initialize rich console
console = Console()

# Create Typer app
app = typer.Typer(
    name="Agera",
    help="Professional DNS & WHOIS enumeration tool for authorized security assessments.",
    add_completion=False,
)

# =============================
# Configuration & Constants
# =============================

OUTPUT_FORMATS = ["txt", "json"]
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

# =============================
# Data Classes
# =============================

@dataclass
class ScanResult:
    """Container for enumeration results."""
    domain: str
    dns_records: Dict[str, List[str]]
    whois_data: Optional[Dict[str, Any]]
    timestamp: str
    duration: float


# =============================
# Banner & Disclaimer
# =============================

def show_banner() -> None:
    """Display ASCII art banner using pyfiglet and rich colors."""
    figlet = Figlet(font="slant")
    banner_text = figlet.renderText("AGERA").strip()
    colored_banner = Text(banner_text, style="bold magenta")
    console.print(colored_banner)
    console.print("\n[dim]Version 1.0 | For Authorized Penetration Testing Only[/dim]\n")


def confirm_authorization() -> bool:
    """
    Prompt user to confirm legal authorization before proceeding.

    Returns:
        bool: True if user confirms authorization.
    """
    panel = Panel(
        "[bold yellow]⚠️  LEGAL DISCLAIMER[/bold yellow]\n\n"
        "This tool is intended for [bold green]authorized security testing[/bold green] only.\n"
        "Using this tool against systems without explicit permission is [bold red]illegal[/bold red].\n\n"
        "You must have written authorization from the system owner before proceeding.\n\n"
        "[bold]Do you confirm that you are authorized to scan the target domain? (y/N):[/bold]",
        title="[bold cyan]Legal Notice[/bold cyan]",
        border_style="red"
    )
    console.print(panel)

    try:
        choice = input("> ").strip().lower()
        return choice in ['y', 'yes']
    except (KeyboardInterrupt, EOFError):
        console.print("\n[red]Scan aborted by user.[/red]")
        return False


# =============================
# DNS Enumeration
# =============================

def resolve_dns_records(domain: str) -> Dict[str, List[str]]:
    """
    Perform DNS enumeration for common record types.

    Args:
        domain (str): Target domain name.

    Returns:
        Dict[str, List[str]]: Mapping of record type to list of values.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    results: Dict[str, List[str]] = {rtype: [] for rtype in DNS_RECORD_TYPES}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        progress.add_task("[cyan]Scanning DNS records...[/cyan]", total=None)

        for rtype in DNS_RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    if rtype == "MX":
                        results[rtype].append(f"{rdata.preference} {rdata.exchange}")
                    elif rtype == "TXT":
                        # Decode TXT records
                        txt_parts = [part.decode() if isinstance(part, bytes) else part for part in rdata.strings]
                        results[rtype].append("".join(txt_parts))
                    elif rtype == "SOA":
                        results[rtype].append(
                            f"{rdata.mname} {rdata.rname} {rdata.serial} {rdata.refresh} {rdata.retry} {rdata.expire} {rdata.minimum}"
                        )
                    else:
                        results[rtype].append(str(rdata))
            except dns.resolver.NXDOMAIN:
                console.print(f"[red]❌ Domain '{domain}' does not exist.[/red]")
                sys.exit(1)
            except dns.resolver.NoAnswer:
                results[rtype] = [f"No {rtype} records found"]
            except dns.resolver.Timeout:
                results[rtype] = [f"Timeout querying {rtype} records"]
            except dns.exception.DNSException as e:
                results[rtype] = [f"DNS error: {str(e)}"]

    return results


# =============================
# WHOIS Lookup
# =============================

def perform_whois_lookup(domain: str) -> Optional[Dict[str, Any]]:
    """
    Perform WHOIS lookup on the given domain.

    Args:
        domain (str): Target domain.

    Returns:
        Optional[Dict[str, Any]]: WHOIS data or None if failed.
    """
    try:
        w = whois.whois(domain)
        if w is None:
            console.print("[yellow]⚠️ WHOIS returned None.[/yellow]")
            return None

        whois_data = {}
        for key, value in w.items():
            if value is None:
                continue
            if isinstance(value, list):
                # Clean and stringify list
                cleaned = [str(v) for v in value if v is not None]
                whois_data[key] = ", ".join(cleaned) if cleaned else "N/A"
            elif isinstance(value, (str, int, float)):
                whois_data[key] = str(value)
            else:
                whois_data[key] = str(value)  # Fallback for dates, etc.

        # Always include key fields even if empty
        essential = ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'name_servers', 'emails']
        for field in essential:
            if field not in whois_data:
                whois_data[field] = "N/A"

        return whois_data

    except Exception as e:
        console.print(f"[red]❌ WHOIS lookup failed: {e}[/red]")
        console.print(f"[dim]Tip: Some domains hide WHOIS via privacy protection.[/dim]")
        return None


# =============================
# Output Formatting
# =============================

def display_results(result: ScanResult) -> None:
    """
    Display scan results in a styled, professional format using rich.

    Args:
        result (ScanResult): The scan results to display.
    """
    console.print(Panel("[bold yellow]🎯 Target Domain[/bold yellow]", border_style="cyan"))

    console.print(f"[bold cyan]Domain:[/bold cyan] {result.domain}")
    console.print(f"[bold cyan]Scan Time:[/bold cyan] {result.timestamp}")
    console.print(f"[bold cyan]Duration:[/bold cyan] {result.duration:.2f}s\n")


    # DNS Records Table
    dns_table = Table(title="🔍 DNS Records", title_style="bold magenta", border_style="bright_black")
    dns_table.add_column("Type", style="bold cyan", justify="left")
    dns_table.add_column("Values", style="green")

    for rtype in DNS_RECORD_TYPES:
        values = result.dns_records.get(rtype, [])
        if values:
            first = True
            for val in values:
                # Safely convert any value to string
                str_val = str(val) if val is not None else "N/A"
                dns_table.add_row(rtype if first else "", str_val)
                first = False
        else:
            dns_table.add_row(rtype, "No records")

    console.print(dns_table)

    # WHOIS Section
    if result.whois_data:
        whois_table = Table(title="📋 WHOIS Information", title_style="bold magenta", border_style="bright_black")
        whois_table.add_column("Field", style="bold cyan", justify="left")
        whois_table.add_column("Value", style="green", overflow="fold")

        # Select key WHOIS fields
        fields = [
            "domain_name", "registrar", "creation_date", "expiration_date",
            "updated_date", "name_servers", "registrant_country", "emails", "org"
        ]

        for field in fields:
            value = result.whois_data.get(field, "N/A")
            if value is None:
                value = "N/A"
            elif isinstance(value, list):
                value = ", ".join(str(v) for v in value if v is not None)
            elif not isinstance(value, str):
                value = str(value)
            whois_table.add_row(field.replace('_', ' ').title(), value)


def save_report(result: ScanResult, output_file: str, output_format: str) -> None:
    """
    Save results to a file in the specified format.

    Args:
        result (ScanResult): Scan results.
        output_file (str): Output file path.
        output_format (str): Format to save ('txt' or 'json').
    """
    try:
        if output_format == "json":
            data = {
                "target": result.domain,
                "timestamp": result.timestamp,
                "duration_seconds": result.duration,
                "dns_records": result.dns_records,
                "whois": result.whois_data
            }
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            console.print(f"[green]✅ JSON report saved to {output_file}[/green]")

        elif output_format == "txt":
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"AGERA SCAN REPORT\n")
                f.write(f"==================\n")
                f.write(f"Target: {result.domain}\n")
                f.write(f"Timestamp: {result.timestamp}\n")
                f.write(f"Duration: {result.duration:.2f} seconds\n\n")

                f.write("DNS RECORDS\n")
                f.write("-----------\n")
                for rtype in DNS_RECORD_TYPES:
                    f.write(f"{rtype}:\n")
                    for val in result.dns_records.get(rtype, []):
                        f.write(f"  → {val}\n")
                    f.write("\n")

                f.write("WHOIS INFORMATION\n")
                f.write("-----------------\n")
                if result.whois_data:
                    for k, v in result.whois_data.items():
                        f.write(f"{k.replace('_', ' ').title()}: {v}\n")
                else:
                    f.write("No WHOIS data available.\n")

            console.print(f"[green]✅ TXT report saved to {output_file}[/green]")

    except Exception as e:
        console.print(f"[red]❌ Failed to save report: {e}[/red]")


# =============================
# Main Command
# =============================

@app.command()
def scan(
    domain: str = typer.Argument(..., help="Target domain to scan"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file path (default: agera_report.{format})"),
    format: str = typer.Option("txt", "-f", "--format", help="Output format: txt or json")
):
    """
    Perform DNS and WHOIS enumeration on the specified DOMAIN.
    """
    # Validate format
    if format not in OUTPUT_FORMATS:
        console.print(f"[red]❌ Invalid format '{format}'. Use: {', '.join(OUTPUT_FORMATS)}[/red]")
        raise typer.Exit(code=1)

    # Show banner
    show_banner()

    # Confirm authorization
    if not confirm_authorization():
        console.print("[red]❌ Authorization not confirmed. Exiting.[/red]")
        raise typer.Exit(code=1)

    # Normalize domain
    domain = domain.lower().strip().rstrip('.')
    if not domain:
        console.print("[red]❌ Invalid domain provided.[/red]")
        raise typer.Exit(code=1)

    # Set default output
    if not output:
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = f"agera_report_{domain}_{timestamp_str}.{format}"

    # Start timer
    start_time = time.time()
    console.print(f"[bold cyan]🚀 Starting enumeration for [underline]{domain}[/underline]...[/bold cyan]\n")

    # Perform DNS scan
    dns_results = resolve_dns_records(domain)

    # Perform WHOIS lookup
    whois_data = perform_whois_lookup(domain)

    # Calculate duration
    duration = time.time() - start_time

    # Build result
    result = ScanResult(
        domain=domain,
        dns_records=dns_results,
        whois_data=whois_data,
        timestamp=datetime.now().isoformat(),
        duration=duration
    )

    # Display results
    display_results(result)

    # Save report
    save_report(result, output, format)

    # Final summary
    console.print(Panel(
        f"[bold green]✔ Scan completed in {duration:.2f}s[/bold green]\n"
        f"📄 Report saved to: [cyan]{output}[/cyan]",
        title="[bold yellow]Summary[/bold yellow]",
        border_style="green"
    ))


# =============================
# Entry Point
# =============================

if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[red]⚠ Scan interrupted by user.[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]❌ Unexpected error: {e}[/red]")
        sys.exit(1)
