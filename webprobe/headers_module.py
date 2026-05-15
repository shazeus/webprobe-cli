"""HTTP headers analysis and security scoring."""

import requests
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


# Security headers and their importance
SECURITY_HEADERS = {
    "Strict-Transport-Security": ("HSTS", 15),
    "Content-Security-Policy": ("CSP", 15),
    "X-Frame-Options": ("X-Frame-Options", 10),
    "X-Content-Type-Options": ("X-Content-Type-Options", 10),
    "Referrer-Policy": ("Referrer-Policy", 5),
    "Permissions-Policy": ("Permissions-Policy", 10),
    "X-XSS-Protection": ("XSS Protection", 5),
    "Cross-Origin-Embedder-Policy": ("COEP", 5),
    "Cross-Origin-Opener-Policy": ("COOP", 5),
    "Cross-Origin-Resource-Policy": ("CORP", 5),
    "Cache-Control": ("Cache-Control", 5),
    "X-Permitted-Cross-Domain-Policies": ("X-Permitted-Cross-Domain-Policies", 5),
}

TECH_SIGNATURES = {
    "X-Powered-By": "server",
    "Server": "server",
    "X-Generator": "cms",
    "X-Drupal-Cache": "Drupal",
    "X-Drupal-Dynamic-Cache": "Drupal",
    "X-WordPress": "WordPress",
    "X-WP-Total": "WordPress",
    "X-Shopify-Stage": "Shopify",
    "X-Joomla-Version": "Joomla",
    "X-AspNet-Version": "ASP.NET",
    "X-AspNetMvc-Version": "ASP.NET MVC",
}

BODY_SIGNATURES = [
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("Joomla!", "Joomla"),
    ("drupal.js", "Drupal"),
    ("/sites/default/files/", "Drupal"),
    ("shopify", "Shopify"),
    ("wix.com", "Wix"),
    ("squarespace.com", "Squarespace"),
    ("__NEXT_DATA__", "Next.js"),
    ("ng-version", "Angular"),
    ("react-root", "React"),
    ("data-reactroot", "React"),
    ("__nuxt", "Nuxt.js"),
    ("gatsby", "Gatsby"),
    ("laravel", "Laravel"),
    ("django", "Django"),
    ("flask", "Flask"),
]


def fetch_headers(url: str, follow_redirects: bool = True, timeout: int = 10) -> Optional[Dict[str, Any]]:
    """Fetch HTTP headers and analyze them."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    session = requests.Session()
    session.max_redirects = 10

    headers_ua = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }

    try:
        response = session.get(
            url,
            headers=headers_ua,
            allow_redirects=follow_redirects,
            timeout=timeout,
            verify=False,
        )
        response_headers = dict(response.headers)

        redirect_chain = []
        if follow_redirects:
            for r in response.history:
                redirect_chain.append((r.status_code, r.url))
        redirect_chain.append((response.status_code, response.url))

        return {
            "url": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "headers": response_headers,
            "redirect_chain": redirect_chain,
            "body_snippet": response.text[:5000] if response.text else "",
            "content_type": response_headers.get("Content-Type", ""),
            "server": response_headers.get("Server", ""),
            "response_time_ms": int(response.elapsed.total_seconds() * 1000),
        }
    except requests.exceptions.SSLError:
        # Retry without SSL verification
        try:
            response = session.get(url, headers=headers_ua, allow_redirects=follow_redirects,
                                   timeout=timeout, verify=False)
            return {
                "url": url,
                "final_url": response.url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "redirect_chain": [(response.status_code, response.url)],
                "body_snippet": response.text[:5000] if response.text else "",
                "content_type": response.headers.get("Content-Type", ""),
                "server": response.headers.get("Server", ""),
                "response_time_ms": int(response.elapsed.total_seconds() * 1000),
                "ssl_error": True,
            }
        except Exception as e:
            return {"error": str(e)}
    except requests.exceptions.ConnectionError as e:
        return {"error": f"Connection error: {e}"}
    except requests.exceptions.Timeout:
        return {"error": "Request timed out"}
    except Exception as e:
        return {"error": str(e)}


def score_security_headers(headers: Dict[str, str]) -> Tuple[int, List[Dict[str, Any]]]:
    """Score security headers, return score (0-100) and details."""
    header_keys_lower = {k.lower(): v for k, v in headers.items()}
    total_points = sum(pts for _, (_, pts) in SECURITY_HEADERS.items())
    earned = 0
    details = []

    for header, (label, points) in SECURITY_HEADERS.items():
        present = header.lower() in header_keys_lower
        value = header_keys_lower.get(header.lower(), "")
        if present:
            earned += points
        details.append({
            "header": header,
            "label": label,
            "present": present,
            "value": value,
            "points": points,
        })

    score = int((earned / total_points) * 100)
    return score, details


def detect_technologies(headers: Dict[str, str], body: str) -> List[str]:
    """Detect technologies from headers and body."""
    technologies = set()
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header, tech_label in TECH_SIGNATURES.items():
        val = headers_lower.get(header.lower(), "")
        if val:
            if tech_label == "server":
                server_name = val.split("/")[0].strip()
                # Skip bare domain names (e.g. github.com) — not useful as tech labels
                if server_name and "." not in server_name:
                    technologies.add(server_name)
                elif server_name and not server_name.replace(".", "").replace("-", "").isalpha():
                    technologies.add(server_name)
            else:
                technologies.add(tech_label if tech_label not in ("server", "cms") else val)

    body_lower = body.lower()
    for signature, tech in BODY_SIGNATURES:
        if signature.lower() in body_lower:
            technologies.add(tech)

    # Cookie-based detection
    cookies = headers_lower.get("set-cookie", "")
    if "laravel_session" in cookies.lower():
        technologies.add("Laravel")
    if "csrftoken" in cookies.lower() or "django" in cookies.lower():
        technologies.add("Django")
    if "phpsessid" in cookies.lower():
        technologies.add("PHP")

    return sorted(technologies)
