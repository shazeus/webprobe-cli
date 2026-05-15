"""CLI entry points for webprobe."""

import socket
import sys
from urllib.parse import urlparse

import click
import requests
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich import box
from rich.text import Text

from webprobe import __version__

console = Console()


def extract_domain(target: str) -> str:
    """Extract bare domain from URL or hostname."""
    target = target.strip()
    if target.startswith(("http://", "https://")):
        return urlparse(target).netloc.split(":")[0]
    return target.split("/")[0].split(":")[0]


def ensure_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


# ─────────────────────────────────────── CLI root ────────────────────────────

@click.group()
@click.version_option(__version__, prog_name="webprobe")
def cli():
    """webprobe — Website reconnaissance toolkit.

    Perform DNS analysis, SSL inspection, header auditing,
    tech-stack detection, WHOIS lookup, and subdomain enumeration.
    """


# ─────────────────────────────────────── dns ─────────────────────────────────

@cli.command("dns")
@click.argument("target")
@click.option("-t", "--types", default=None, help="Comma-separated record types (e.g. A,MX,TXT)")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def dns_cmd(target, types, output_json):
    """Enumerate DNS records for a domain."""
    from webprobe.dns_module import resolve_records, check_dnssec, get_nameservers

    domain = extract_domain(target)
    record_types = [t.strip().upper() for t in types.split(",")] if types else None

    with console.status(f"[bold cyan]Resolving DNS records for [green]{domain}[/green]…"):
        records = resolve_records(domain, record_types)
        dnssec = check_dnssec(domain)

    if output_json:
        import json
        console.print_json(json.dumps({"domain": domain, "dnssec": dnssec, "records": records}))
        return

    console.print()
    console.print(Panel(
        f"[bold cyan]DNS Records[/bold cyan]  [dim]|[/dim]  [green]{domain}[/green]  "
        f"[dim]|[/dim]  DNSSEC: {'[green]Yes[/green]' if dnssec else '[red]No[/red]'}",
        box=box.ROUNDED,
    ))

    if not records:
        console.print("[yellow]No records found.[/yellow]")
        return

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold magenta")
    table.add_column("Type", style="cyan", width=8)
    table.add_column("Value", style="white")

    for rtype, values in sorted(records.items()):
        for i, val in enumerate(values):
            table.add_row(rtype if i == 0 else "", val)
        if len(values) > 1:
            table.add_row("", "")

    console.print(table)
    console.print(f"[dim]  {sum(len(v) for v in records.values())} records across {len(records)} types[/dim]\n")


# ─────────────────────────────────────── ssl ─────────────────────────────────

@cli.command("ssl")
@click.argument("target")
@click.option("-p", "--port", default=443, show_default=True, help="HTTPS port")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def ssl_cmd(target, port, output_json):
    """Analyze SSL/TLS certificate for a host."""
    from webprobe.ssl_module import get_ssl_info

    domain = extract_domain(target)

    with console.status(f"[bold cyan]Fetching SSL certificate from [green]{domain}:{port}[/green]…"):
        info = get_ssl_info(domain, port)

    if output_json:
        import json
        def _serial(obj):
            if hasattr(obj, "isoformat"):
                return obj.isoformat()
            return str(obj)
        console.print_json(json.dumps(info, default=_serial))
        return

    if not info or "error" in info:
        console.print(Panel(f"[red]Error:[/red] {info.get('error', 'Unknown error')}", box=box.ROUNDED))
        return

    console.print()

    days = info.get("days_remaining")
    if days is None:
        expiry_color = "yellow"
        expiry_str = "Unknown"
    elif days < 14:
        expiry_color = "red"
        expiry_str = f"{days} days (CRITICAL)"
    elif days < 30:
        expiry_color = "yellow"
        expiry_str = f"{days} days (warning)"
    else:
        expiry_color = "green"
        expiry_str = f"{days} days"

    table = Table(box=box.SIMPLE_HEAD, show_header=False)
    table.add_column("Field", style="bold cyan", width=24)
    table.add_column("Value", style="white")

    table.add_row("Subject CN", info.get("subject_cn", ""))
    table.add_row("Issuer", f"{info.get('issuer_cn', '')} ({info.get('issuer_org', '')})")
    table.add_row("Protocol", info.get("protocol", ""))
    table.add_row("Cipher", f"{info.get('cipher_name', '')} ({info.get('cipher_bits', '')} bit)")
    table.add_row("Valid From", str(info.get("not_before", "")) if info.get("not_before") else "")
    table.add_row("Expires", str(info.get("not_after", "")) if info.get("not_after") else "")
    table.add_row("Days Remaining", f"[{expiry_color}]{expiry_str}[/{expiry_color}]")
    table.add_row("Wildcard Cert", "[green]Yes[/green]" if info.get("wildcard") else "No")
    table.add_row("SANs", f"{info.get('san_count', 0)} entries")
    table.add_row("Serial Number", info.get("serial", ""))

    console.print(Panel("[bold cyan]SSL/TLS Certificate Analysis[/bold cyan]", box=box.ROUNDED))
    console.print(table)

    sans = info.get("sans", [])
    if sans:
        console.print("\n[bold]Subject Alternative Names:[/bold]")
        for san in sans[:10]:
            console.print(f"  [dim]•[/dim] {san}")
        if info.get("san_count", 0) > 10:
            console.print(f"  [dim]… and {info['san_count'] - 10} more[/dim]")
    console.print()


# ─────────────────────────────────────── headers ─────────────────────────────

@cli.command("headers")
@click.argument("target")
@click.option("--no-redirect", is_flag=True, help="Don't follow redirects")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def headers_cmd(target, no_redirect, output_json):
    """Fetch and display HTTP response headers."""
    from webprobe.headers_module import fetch_headers

    url = ensure_url(target)

    with console.status(f"[bold cyan]Fetching headers from [green]{url}[/green]…"):
        result = fetch_headers(url, follow_redirects=not no_redirect)

    if not result or "error" in result:
        console.print(f"[red]Error:[/red] {result.get('error', 'Unknown') if result else 'No response'}")
        return

    if output_json:
        import json
        console.print_json(json.dumps(result))
        return

    console.print()
    status = result["status_code"]
    status_color = "green" if status < 300 else ("yellow" if status < 400 else "red")

    console.print(Panel(
        f"[bold cyan]HTTP Headers[/bold cyan]  [dim]|[/dim]  "
        f"[{status_color}]{status}[/{status_color}]  [dim]|[/dim]  "
        f"{result['final_url']}  [dim]|[/dim]  {result['response_time_ms']}ms",
        box=box.ROUNDED,
    ))

    if len(result["redirect_chain"]) > 1:
        console.print("[dim]Redirect chain:[/dim]")
        for code, loc in result["redirect_chain"]:
            console.print(f"  [dim]→[/dim] [{status_color}]{code}[/{status_color}] {loc}")
        console.print()

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold magenta")
    table.add_column("Header", style="cyan", width=36)
    table.add_column("Value", style="white")

    for k, v in sorted(result["headers"].items()):
        table.add_row(k, v[:120] + ("…" if len(v) > 120 else ""))

    console.print(table)
    console.print()


# ─────────────────────────────────────── tech ────────────────────────────────

@cli.command("tech")
@click.argument("target")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def tech_cmd(target, output_json):
    """Detect technology stack from headers and page content."""
    from webprobe.headers_module import fetch_headers, detect_technologies, score_security_headers

    url = ensure_url(target)

    with console.status(f"[bold cyan]Detecting tech stack for [green]{url}[/green]…"):
        result = fetch_headers(url)

    if not result or "error" in result:
        console.print(f"[red]Error:[/red] {result.get('error', 'Unknown') if result else 'No response'}")
        return

    headers = result.get("headers", {})
    body = result.get("body_snippet", "")
    technologies = detect_technologies(headers, body)
    score, sec_details = score_security_headers(headers)

    if output_json:
        import json
        console.print_json(json.dumps({
            "url": result["final_url"],
            "technologies": technologies,
            "security_score": score,
            "security_headers": sec_details,
        }))
        return

    score_color = "green" if score >= 70 else ("yellow" if score >= 40 else "red")

    console.print()
    console.print(Panel(
        f"[bold cyan]Tech Stack Detection[/bold cyan]  [dim]|[/dim]  "
        f"[green]{result['final_url']}[/green]  [dim]|[/dim]  "
        f"Security Score: [{score_color}]{score}/100[/{score_color}]",
        box=box.ROUNDED,
    ))

    if technologies:
        console.print("\n[bold]Detected Technologies:[/bold]")
        for tech in technologies:
            console.print(f"  [green]✓[/green] {tech}")
    else:
        console.print("\n[yellow]No technologies detected.[/yellow]")

    console.print("\n[bold]Security Headers:[/bold]")
    sec_table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold magenta")
    sec_table.add_column("Header", style="cyan")
    sec_table.add_column("Status", no_wrap=True)
    sec_table.add_column("Pts", no_wrap=True)
    sec_table.add_column("Value", style="dim")

    for item in sec_details:
        status_text = "[green]Present[/green]" if item["present"] else "[red]Missing[/red]"
        val = item["value"][:38] + ("…" if len(item["value"]) > 38 else "") if item["value"] else ""
        sec_table.add_row(item["header"], status_text, str(item["points"]), val)

    console.print(sec_table)
    console.print()


# ─────────────────────────────────────── whois ───────────────────────────────

@cli.command("whois")
@click.argument("target")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def whois_cmd(target, output_json):
    """Perform WHOIS lookup for a domain."""
    from webprobe.whois_module import lookup

    domain = extract_domain(target)

    with console.status(f"[bold cyan]Querying WHOIS for [green]{domain}[/green]…"):
        info = lookup(domain)

    if output_json:
        import json
        def _serial(obj):
            if hasattr(obj, "isoformat"):
                return obj.isoformat()
            return str(obj)
        console.print_json(json.dumps(info, default=_serial))
        return

    if "error" in info:
        console.print(Panel(f"[red]WHOIS Error:[/red] {info['error']}", box=box.ROUNDED))
        return

    console.print()
    console.print(Panel(f"[bold cyan]WHOIS Lookup[/bold cyan]  [dim]|[/dim]  [green]{domain}[/green]", box=box.ROUNDED))

    table = Table(box=box.SIMPLE_HEAD, show_header=False)
    table.add_column("Field", style="bold cyan", width=22)
    table.add_column("Value", style="white")

    def fmt_date(d):
        return d.strftime("%Y-%m-%d %H:%M UTC") if d else "N/A"

    table.add_row("Registrar", info.get("registrar") or "N/A")
    table.add_row("Registrant Org", info.get("registrant_org") or "N/A")
    table.add_row("Country", info.get("registrant_country") or "N/A")
    table.add_row("Created", fmt_date(info.get("creation_date")))
    table.add_row("Expires", fmt_date(info.get("expiration_date")))
    table.add_row("Updated", fmt_date(info.get("updated_date")))
    table.add_row("DNSSEC", info.get("dnssec") or "N/A")

    ns = info.get("name_servers", [])
    if ns:
        table.add_row("Name Servers", ns[0])
        for n in ns[1:]:
            table.add_row("", n)

    status = info.get("status", [])
    if status:
        table.add_row("Status", status[0][:80] if status[0] else "")
        for s in status[1:3]:
            table.add_row("", s[:80] if s else "")

    console.print(table)
    console.print()


# ─────────────────────────────────────── subdomains ──────────────────────────

@cli.command("subdomains")
@click.argument("target")
@click.option("-w", "--wordlist", default=None, help="Path to custom wordlist file")
@click.option("-t", "--threads", default=30, show_default=True, help="Number of concurrent threads")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def subdomains_cmd(target, wordlist, threads, output_json):
    """Enumerate subdomains via DNS brute-force."""
    from webprobe.subdomain_module import enumerate_subdomains, COMMON_SUBDOMAINS

    domain = extract_domain(target)

    words = COMMON_SUBDOMAINS
    if wordlist:
        try:
            with open(wordlist) as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"[red]Wordlist not found:[/red] {wordlist}")
            sys.exit(1)

    console.print()
    console.print(Panel(
        f"[bold cyan]Subdomain Enumeration[/bold cyan]  [dim]|[/dim]  [green]{domain}[/green]  "
        f"[dim]|[/dim]  {len(words)} candidates  [dim]|[/dim]  {threads} threads",
        box=box.ROUNDED,
    ))

    found = []
    progress_state = {"done": 0}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"Scanning {domain}…", total=len(words))

        def cb(done, total):
            progress_state["done"] = done
            progress.update(task, completed=done)

        found = enumerate_subdomains(domain, words, threads=threads, progress_cb=cb)

    if output_json:
        import json
        console.print_json(json.dumps({"domain": domain, "found": len(found), "subdomains": found}))
        return

    if found:
        console.print(f"\n[green]Found {len(found)} subdomains:[/green]\n")
        for entry in found:
            parts = entry.split(" -> ")
            sub = parts[0]
            ip = parts[1] if len(parts) > 1 else ""
            console.print(f"  [cyan]{sub:<45}[/cyan]  [dim]{ip}[/dim]")
    else:
        console.print("\n[yellow]No subdomains found with the current wordlist.[/yellow]")
    console.print()


# ─────────────────────────────────────── scan (full recon) ───────────────────

@cli.command("scan")
@click.argument("target")
@click.option("--skip-whois", is_flag=True, help="Skip WHOIS lookup")
@click.option("--skip-subdomains", is_flag=True, help="Skip subdomain enumeration")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def scan_cmd(target, skip_whois, skip_subdomains, output_json):
    """Full reconnaissance scan (DNS + SSL + headers + tech + WHOIS)."""
    from webprobe.dns_module import resolve_records, check_dnssec
    from webprobe.ssl_module import get_ssl_info
    from webprobe.headers_module import fetch_headers, detect_technologies, score_security_headers
    from webprobe.whois_module import lookup as whois_lookup
    from webprobe.subdomain_module import enumerate_subdomains

    domain = extract_domain(target)
    url = ensure_url(target)

    if not output_json:
        console.print()
        console.print(Panel(
            f"[bold cyan]Full Reconnaissance Scan[/bold cyan]\n[green]{domain}[/green]",
            box=box.DOUBLE_EDGE,
        ))

    results = {}

    with console.status("[bold cyan]Running DNS enumeration…") if not output_json else _null_context():
        results["dns"] = resolve_records(domain)
        results["dnssec"] = check_dnssec(domain)

    with console.status("[bold cyan]Analyzing SSL certificate…") if not output_json else _null_context():
        results["ssl"] = get_ssl_info(domain)

    with console.status("[bold cyan]Fetching HTTP headers…") if not output_json else _null_context():
        results["http"] = fetch_headers(url)

    if results.get("http") and "error" not in results["http"]:
        headers = results["http"].get("headers", {})
        body = results["http"].get("body_snippet", "")
        results["technologies"] = detect_technologies(headers, body)
        results["security_score"], results["security_details"] = score_security_headers(headers)
    else:
        results["technologies"] = []
        results["security_score"] = 0
        results["security_details"] = []

    if not skip_whois:
        with console.status("[bold cyan]Querying WHOIS…") if not output_json else _null_context():
            results["whois"] = whois_lookup(domain)

    if output_json:
        import json
        def _serial(obj):
            if hasattr(obj, "isoformat"):
                return obj.isoformat()
            return str(obj)
        console.print_json(json.dumps(results, default=_serial))
        return

    # ── DNS summary ───────────────────────────────────────────────────────────
    console.print("\n[bold underline cyan]DNS Records[/bold underline cyan]")
    dns_table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold magenta")
    dns_table.add_column("Type", style="cyan", width=8)
    dns_table.add_column("Value")
    for rtype, values in sorted(results["dns"].items()):
        for i, val in enumerate(values):
            dns_table.add_row(rtype if i == 0 else "", val)
    console.print(dns_table)

    # ── SSL summary ───────────────────────────────────────────────────────────
    ssl_info = results.get("ssl", {})
    if ssl_info and "error" not in ssl_info:
        days = ssl_info.get("days_remaining")
        days_color = "green" if (days or 0) > 30 else ("yellow" if (days or 0) > 14 else "red")
        console.print("\n[bold underline cyan]SSL Certificate[/bold underline cyan]")
        ssl_table = Table(box=box.SIMPLE_HEAD, show_header=False)
        ssl_table.add_column("Field", style="bold cyan", width=20)
        ssl_table.add_column("Value")
        ssl_table.add_row("Subject CN", ssl_info.get("subject_cn", ""))
        ssl_table.add_row("Issuer", ssl_info.get("issuer_cn", ""))
        ssl_table.add_row("Protocol", ssl_info.get("protocol", ""))
        ssl_table.add_row("Expires in", f"[{days_color}]{days} days[/{days_color}]" if days else "N/A")
        console.print(ssl_table)

    # ── Technologies ──────────────────────────────────────────────────────────
    techs = results.get("technologies", [])
    console.print("\n[bold underline cyan]Technologies[/bold underline cyan]")
    if techs:
        for t in techs:
            console.print(f"  [green]✓[/green] {t}")
    else:
        console.print("  [dim]None detected[/dim]")

    # ── Security score ────────────────────────────────────────────────────────
    score = results.get("security_score", 0)
    sc = "green" if score >= 70 else ("yellow" if score >= 40 else "red")
    console.print(f"\n[bold underline cyan]Security Header Score[/bold underline cyan]  [{sc}]{score}/100[/{sc}]")

    # ── WHOIS summary ─────────────────────────────────────────────────────────
    if not skip_whois:
        w = results.get("whois", {})
        if w and "error" not in w:
            console.print("\n[bold underline cyan]WHOIS[/bold underline cyan]")
            wt = Table(box=box.SIMPLE_HEAD, show_header=False)
            wt.add_column("Field", style="bold cyan", width=20)
            wt.add_column("Value")
            wt.add_row("Registrar", w.get("registrar") or "N/A")
            wt.add_row("Country", w.get("registrant_country") or "N/A")
            def fmt(d):
                return d.strftime("%Y-%m-%d") if d else "N/A"
            wt.add_row("Created", fmt(w.get("creation_date")))
            wt.add_row("Expires", fmt(w.get("expiration_date")))
            console.print(wt)

    console.print()


class _null_context:
    def __enter__(self):
        return self
    def __exit__(self, *_):
        pass
