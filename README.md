<p align="center">
  <h1 align="center">webprobe</h1>
  <p align="center">Website reconnaissance toolkit — DNS, SSL, headers, tech-stack, WHOIS & subdomains from one CLI.</p>
  <p align="center">
    <a href="https://pypi.org/project/webprobe-cli/"><img src="https://img.shields.io/pypi/v/webprobe-cli?color=blue&label=PyPI" alt="PyPI"></a>
    <a href="https://pypi.org/project/webprobe-cli/"><img src="https://img.shields.io/pypi/pyversions/webprobe-cli" alt="Python"></a>
    <a href="https://github.com/shazeus/webprobe-cli/blob/main/LICENSE"><img src="https://img.shields.io/github/license/shazeus/webprobe-cli" alt="License"></a>
    <a href="https://github.com/shazeus/webprobe-cli/stargazers"><img src="https://img.shields.io/github/stars/shazeus/webprobe-cli?style=flat" alt="Stars"></a>
  </p>
</p>

---

**webprobe** is a fast, beautiful command-line website reconnaissance toolkit for developers, security researchers, and sysadmins. Point it at any domain or URL to instantly gather DNS records, inspect SSL certificates, audit HTTP security headers, detect the technology stack, query WHOIS registration data, and brute-force subdomains — all with rich, colour-coded terminal output.

- **DNS enumeration** — Resolve A, AAAA, MX, NS, TXT, CNAME, SOA, CAA records and DNSSEC status in one shot
- **SSL/TLS analysis** — Certificate chain, expiry countdown, cipher suite, SANs, wildcard detection
- **HTTP header audit** — Full header dump with redirect chain and response-time tracking
- **Security scoring** — Grade security headers (HSTS, CSP, X-Frame-Options, Permissions-Policy…) out of 100
- **Tech-stack detection** — Identify frameworks, CMSs, servers, and languages from headers and page content
- **WHOIS lookup** — Registrar, registrant, creation/expiry dates, name servers and domain status
- **Subdomain enumeration** — Multi-threaded DNS brute-force with a built-in 150-word list or your own
- **Full scan mode** — Run every module at once with a single command
- **JSON output** — Every command supports `--json` for pipeline-friendly output

## Installation

```bash
pip install webprobe-cli
```

Requires Python 3.9+.

## Usage

```bash
# Quick full scan
webprobe scan example.com

# Individual modules
webprobe dns    example.com
webprobe ssl    example.com
webprobe headers example.com
webprobe tech   example.com
webprobe whois  example.com
webprobe subdomains example.com

# JSON output (pipe-friendly)
webprobe dns example.com --json | jq '.records.MX'

# Subdomain enum with custom wordlist
webprobe subdomains example.com -w /path/to/wordlist.txt -t 50
```

## Commands

| Command | Description |
|---------|-------------|
| `webprobe scan <target>` | Full recon — runs all modules in sequence |
| `webprobe dns <target>` | DNS record enumeration (A, MX, NS, TXT, CNAME, SOA, CAA…) |
| `webprobe ssl <target>` | SSL/TLS certificate analysis and expiry check |
| `webprobe headers <target>` | HTTP response header inspection |
| `webprobe tech <target>` | Technology stack detection + security header scoring |
| `webprobe whois <target>` | WHOIS domain registration data |
| `webprobe subdomains <target>` | Multi-threaded subdomain brute-force enumeration |

### Global options

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON (supported by all commands) |
| `--version` | Show webprobe version |
| `--help` | Show help for any command |

### Command-specific options

| Command | Option | Description |
|---------|--------|-------------|
| `dns` | `-t/--types A,MX,TXT` | Restrict to specific record types |
| `ssl` | `-p/--port 443` | Custom HTTPS port |
| `headers` | `--no-redirect` | Do not follow HTTP redirects |
| `subdomains` | `-w/--wordlist <file>` | Custom wordlist file |
| `subdomains` | `-t/--threads 30` | Concurrency level (default 30) |
| `scan` | `--skip-whois` | Skip WHOIS lookup |
| `scan` | `--skip-subdomains` | Skip subdomain enumeration |

## Configuration

No configuration file is required. All options are passed as CLI flags.

For repeated scans, combine with standard Unix tools:

```bash
# Scan a list of domains
while IFS= read -r domain; do webprobe scan "$domain" --json; done < domains.txt

# Alert on certificates expiring within 30 days
webprobe ssl example.com --json | jq -e '.days_remaining > 30' || echo "Certificate expiring soon!"
```

## License

MIT © [shazeus](https://github.com/shazeus)
