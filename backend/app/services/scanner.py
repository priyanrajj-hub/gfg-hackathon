"""
Real, non-AI vulnerability checks. These are deterministic HTTP/TLS inspections —
NOT dressed up as AI. AI is used separately (services/ai.py) only to summarize
and prioritize what this scanner finds, per the BYOK rule.
"""
import hashlib
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

import httpx

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


async def fetch_site(url: str) -> httpx.Response:
    async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
        return await client.get(url)


def check_headers(headers: httpx.Headers) -> dict:
    lower_headers = {k.lower(): v for k, v in headers.items()}
    findings = {}
    for h in SECURITY_HEADERS:
        findings[h] = {"present": h in lower_headers, "value": lower_headers.get(h)}
    # Cookie security
    set_cookie = lower_headers.get("set-cookie", "")
    findings["cookie_secure"] = "secure" in set_cookie.lower()
    findings["cookie_httponly"] = "httponly" in set_cookie.lower()
    return findings


def check_cors(headers: httpx.Headers) -> dict:
    acao = headers.get("access-control-allow-origin")
    return {"access_control_allow_origin": acao, "wildcard_risk": acao == "*"}


def check_ssl_expiry(hostname: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.utcnow()).days
        return {"valid": True, "expires": not_after.isoformat(), "days_left": days_left}
    except Exception as e:
        return {"valid": False, "error": str(e)}


async def run_full_scan(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or url

    result = {"url": url, "scanned_at": datetime.utcnow().isoformat()}
    try:
        resp = await fetch_site(url)
        result["status_code"] = resp.status_code
        result["headers"] = check_headers(resp.headers)
        result["cors"] = check_cors(resp.headers)
        result["html_hash"] = hashlib.sha256(resp.content).hexdigest()
        result["content_length"] = len(resp.content)
    except Exception as e:
        result["fetch_error"] = str(e)

    if parsed.scheme == "https":
        result["ssl"] = check_ssl_expiry(hostname)
    else:
        result["ssl"] = {"valid": False, "error": "Not served over HTTPS"}

    return result


def score_from_scan(scan: dict) -> int:
    """Simple deterministic point-based scoring — transparent, not a black box."""
    score = 100
    headers = scan.get("headers", {})
    for h in SECURITY_HEADERS:
        if not headers.get(h, {}).get("present"):
            score -= 8
    if scan.get("cors", {}).get("wildcard_risk"):
        score -= 15
    ssl_info = scan.get("ssl", {})
    if not ssl_info.get("valid"):
        score -= 20
    elif ssl_info.get("days_left", 999) < 14:
        score -= 10
    if not headers.get("cookie_secure"):
        score -= 5
    if not headers.get("cookie_httponly"):
        score -= 5
    return max(score, 0)
