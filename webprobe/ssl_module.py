"""SSL/TLS certificate analysis."""

import socket
import ssl
from datetime import datetime
from typing import Any, Dict, Optional


def get_ssl_info(hostname: str, port: int = 443) -> Optional[Dict[str, Any]]:
    """Retrieve and analyze SSL certificate info."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

                # Parse subject / issuer
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))

                # Parse SANs
                sans = []
                for typ, val in cert.get("subjectAltName", []):
                    if typ == "DNS":
                        sans.append(val)

                # Parse expiry
                not_after_str = cert.get("notAfter", "")
                not_before_str = cert.get("notBefore", "")
                try:
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
                    days_remaining = (not_after - datetime.utcnow()).days
                except ValueError:
                    not_after = None
                    not_before = None
                    days_remaining = None

                return {
                    "subject_cn": subject.get("commonName", ""),
                    "issuer_org": issuer.get("organizationName", ""),
                    "issuer_cn": issuer.get("commonName", ""),
                    "not_before": not_before,
                    "not_after": not_after,
                    "days_remaining": days_remaining,
                    "san_count": len(sans),
                    "sans": sans[:15],
                    "protocol": protocol,
                    "cipher_name": cipher[0] if cipher else "unknown",
                    "cipher_bits": cipher[2] if cipher else 0,
                    "serial": cert.get("serialNumber", ""),
                    "version": cert.get("version", 0),
                    "wildcard": any(s.startswith("*.") for s in sans),
                }
    except ssl.SSLError as e:
        return {"error": f"SSL error: {e}"}
    except socket.timeout:
        return {"error": "Connection timed out"}
    except ConnectionRefusedError:
        return {"error": "Connection refused"}
    except Exception as e:
        return {"error": str(e)}
