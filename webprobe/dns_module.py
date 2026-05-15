"""DNS record lookup and analysis."""

import dns.resolver
import dns.reversename
import socket
from typing import Dict, List, Optional


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "PTR"]


def resolve_records(domain: str, record_types: Optional[List[str]] = None) -> Dict[str, List[str]]:
    """Resolve DNS records for a domain."""
    if record_types is None:
        record_types = RECORD_TYPES

    results: Dict[str, List[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            results[rtype] = [str(r) for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            pass
        except Exception:
            pass

    return results


def reverse_dns(ip: str) -> Optional[str]:
    """Perform reverse DNS lookup."""
    try:
        rev_name = dns.reversename.from_address(ip)
        answer = dns.resolver.resolve(rev_name, "PTR")
        return str(answer[0]).rstrip(".")
    except Exception:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None


def get_nameservers(domain: str) -> List[str]:
    """Get authoritative nameservers for a domain."""
    try:
        answers = dns.resolver.resolve(domain, "NS")
        return [str(r).rstrip(".") for r in answers]
    except Exception:
        return []


def check_dnssec(domain: str) -> bool:
    """Check if DNSSEC is enabled."""
    try:
        answers = dns.resolver.resolve(domain, "DNSKEY")
        return len(answers) > 0
    except Exception:
        return False
