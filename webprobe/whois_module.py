"""WHOIS lookup and parsing."""

import whois
from typing import Any, Dict, List, Optional
from datetime import datetime


def lookup(domain: str) -> Dict[str, Any]:
    """Perform WHOIS lookup for a domain."""
    try:
        w = whois.whois(domain)
        if w is None:
            return {"error": "No WHOIS data returned"}

        def coerce_date(val):
            if isinstance(val, list):
                val = val[0]
            if isinstance(val, datetime):
                return val
            return None

        def coerce_list(val):
            if val is None:
                return []
            if isinstance(val, list):
                return [str(v) for v in val if v]
            return [str(val)]

        registrar = w.get("registrar") or ""
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else ""

        return {
            "domain_name": domain,
            "registrar": str(registrar),
            "registrant_org": str(w.get("org") or w.get("registrant_organization") or ""),
            "registrant_country": str(w.get("country") or ""),
            "creation_date": coerce_date(w.get("creation_date")),
            "expiration_date": coerce_date(w.get("expiration_date")),
            "updated_date": coerce_date(w.get("updated_date")),
            "name_servers": coerce_list(w.get("name_servers")),
            "status": coerce_list(w.get("status")),
            "emails": coerce_list(w.get("emails")),
            "dnssec": str(w.get("dnssec") or "unsigned"),
        }
    except Exception as e:
        return {"error": str(e)}
