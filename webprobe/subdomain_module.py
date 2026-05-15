"""Subdomain enumeration via DNS brute-force."""

import concurrent.futures
import dns.resolver
from typing import Callable, List, Optional

# Common subdomains wordlist (top ~150)
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "blog", "webdisk", "ns", "api", "dev", "m", "staging", "app", "test",
    "vpn", "admin", "portal", "secure", "shop", "store", "direct", "cdn",
    "static", "assets", "media", "img", "images", "video", "support", "help",
    "status", "docs", "api2", "beta", "alpha", "demo", "new", "old", "backup",
    "git", "svn", "jira", "confluence", "jenkins", "ci", "monitor", "grafana",
    "kibana", "elastic", "search", "db", "mysql", "postgres", "redis", "mongo",
    "minio", "s3", "bucket", "upload", "download", "files", "data", "report",
    "analytics", "track", "pixel", "ads", "ad", "login", "auth", "sso", "oauth",
    "account", "accounts", "user", "users", "member", "members", "client",
    "clients", "partner", "partners", "vendor", "vendors", "hub", "gateway",
    "proxy", "load", "lb", "edge", "origin", "primary", "secondary", "master",
    "slave", "replica", "cluster", "node", "worker", "queue", "broker",
    "chat", "forum", "community", "wiki", "knowledge", "kb", "feedback",
    "survey", "newsletter", "news", "press", "blog2", "careers", "jobs",
    "about", "contact", "legal", "privacy", "terms", "tos", "policy",
    "payments", "billing", "invoice", "dashboard", "panel", "control",
    "manage", "management", "internal", "intranet", "extranet", "vpn2",
    "remote", "office", "corp", "corporate", "enterprise", "b2b", "b2c",
    "sandbox", "local", "preview", "stage", "uat", "qa", "production", "prod",
    "web", "web2", "web3", "api3", "v1", "v2", "v3", "service", "services",
    "microservice", "micro", "graphql", "rest", "soap", "grpc", "rpc",
    "smtp2", "mail2", "imap", "pop3", "webmail2", "exchange", "owa",
    "autodiscover", "autoconfig", "cpanel", "whm", "plesk", "directadmin",
]


def resolve_subdomain(subdomain: str, domain: str) -> Optional[str]:
    """Resolve a single subdomain. Returns FQDN if found, None otherwise."""
    fqdn = f"{subdomain}.{domain}"
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5
    try:
        answers = resolver.resolve(fqdn, "A")
        ips = [str(r) for r in answers]
        return f"{fqdn} -> {', '.join(ips)}"
    except Exception:
        pass
    try:
        answers = resolver.resolve(fqdn, "CNAME")
        targets = [str(r).rstrip(".") for r in answers]
        return f"{fqdn} -> CNAME: {', '.join(targets)}"
    except Exception:
        return None


def enumerate_subdomains(
    domain: str,
    wordlist: Optional[List[str]] = None,
    threads: int = 30,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> List[str]:
    """Enumerate subdomains using DNS brute-force."""
    words = wordlist or COMMON_SUBDOMAINS
    found = []
    total = len(words)
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(resolve_subdomain, w, domain): w for w in words}
        for future in concurrent.futures.as_completed(futures):
            done += 1
            if progress_cb:
                progress_cb(done, total)
            result = future.result()
            if result:
                found.append(result)

    return sorted(found)
