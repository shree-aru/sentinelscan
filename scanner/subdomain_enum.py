"""
SentinelScan - Subdomain Enumeration Module
============================================
Module 9: Discovers subdomains of the target using Certificate
Transparency logs via the free crt.sh API.

Real-world importance:
  - Subdomains expand the attack surface dramatically
  - "example.com" may be secure but "dev.example.com" or "api.example.com"
    might have outdated software or weaker security
  - Bug bounty hunters start EVERY engagement with subdomain enumeration
  - Tools like Amass, Subfinder, and Assetfinder do exactly this

How Certificate Transparency works:
  - All publicly-trusted SSL certificates must be logged in Certificate
    Transparency (CT) logs (this is a Google/browser requirement)
  - crt.sh is a searchable database of ALL issued SSL certificates
  - When you search for *.example.com, every subdomain that ever had
    an SSL cert issued appears in the results
  - This is passive — we only query crt.sh, we never touch the target

Why crt.sh is the best free source:
  - No API key required
  - No rate limit for reasonable use  
  - Covers ALL trusted CAs (Let's Encrypt, DigiCert, Comodo, etc.)
  - Data is publicly available by design (it's a transparency log)
  - Used by: security researchers, bug bounty hunters, red teams globally

After finding subdomains, this module also probes each one for
basic HTTP reachability — flagging live subdomains that could be
independently audited.

Learning goals:
  - Working with JSON REST APIs
  - Set operations for deduplication
  - DNS resolution with socket module
  - Concurrent HTTP probing with ThreadPoolExecutor
"""

import socket
import concurrent.futures
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

from scanner.models import Finding, ModuleResult, Severity


CRT_SH_URL = "https://crt.sh/?q=%.{domain}&output=json"

# We probe discovered subdomains with this timeout per request
PROBE_TIMEOUT = 5

# Max concurrent probes — be respectful, don't flood
MAX_WORKERS = 10


def _extract_domain(target: str) -> str:
    """Extract the base domain from a URL."""
    parsed = urlparse(target)
    host = parsed.hostname or target
    # Remove 'www.' prefix if present
    if host.startswith("www."):
        host = host[4:]
    return host


def _query_crtsh(domain: str) -> list[str]:
    """
    Query crt.sh for all subdomains with SSL certs issued for the domain.

    Returns a sorted, deduplicated list of subdomain strings.
    """
    url = CRT_SH_URL.format(domain=domain)
    try:
        response = requests.get(url, timeout=15)
        if response.status_code != 200:
            return []

        data = response.json()
        subdomains = set()

        for cert in data:
            # name_value can contain multiple names separated by newlines
            names = cert.get("name_value", "").lower().split("\n")
            for name in names:
                name = name.strip().lstrip("*.")  # Remove wildcard prefix
                # Only include names that are subdomains of our target
                if name.endswith(f".{domain}") and name != domain:
                    # Skip common noise entries
                    if not name.startswith("@") and "." in name:
                        subdomains.add(name)

        return sorted(subdomains)

    except (RequestException, ValueError):
        return []


def _probe_subdomain(subdomain: str) -> dict | None:
    """
    Try to connect to a subdomain over HTTP/HTTPS.

    Returns a dict with status info, or None if unreachable.
    This tells us which discovered subdomains are actually live.
    """
    for scheme in ("https", "http"):
        try:
            url = f"{scheme}://{subdomain}"
            response = requests.get(
                url,
                timeout=PROBE_TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": "SentinelScan/1.0 (Authorized Security Testing)"}
            )
            return {
                "subdomain": subdomain,
                "url": url,
                "status": response.status_code,
                "server": response.headers.get("Server", ""),
                "final_url": response.url,
            }
        except RequestException:
            continue
    return None


def _resolve_ip(subdomain: str) -> str | None:
    """DNS resolve a subdomain to IPv4."""
    try:
        return socket.gethostbyname(subdomain)
    except socket.gaierror:
        return None


class SubdomainEnumerator:
    """
    Discovers subdomains using Certificate Transparency logs and
    probes them for live HTTP services.

    Usage:
        enumerator = SubdomainEnumerator()
        result = enumerator.check("https://example.com")
    """

    def __init__(self, timeout: int = 10, probe: bool = True):
        self.timeout = timeout
        self.probe = probe  # Whether to probe discovered subdomains for liveness

    def check(self, target: str) -> ModuleResult:
        """
        Run subdomain enumeration for the target domain.

        Steps:
          1. Extract base domain from target URL
          2. Query crt.sh for subdomains with SSL certs
          3. Probe each subdomain for HTTP reachability
          4. Flag interesting or suspicious subdomains

        Args:
            target: Target URL (e.g., https://example.com)

        Returns:
            ModuleResult with discovered subdomains as findings/passed
        """
        result = ModuleResult(
            module_name="Subdomain Enumeration",
            target=target
        )

        domain = _extract_domain(target)
        result.passed.append(f"Base domain: {domain}")

        # ── Step 1: Query crt.sh ─────────────────────────────────────────────
        subdomains = _query_crtsh(domain)

        if not subdomains:
            result.passed.append(
                "No subdomains found in Certificate Transparency logs. "
                "This could mean the domain is new, uses only wildcard certs, "
                "or has minimal subdomain usage."
            )
            return result

        result.passed.append(
            f"Certificate Transparency logs reveal {len(subdomains)} "
            f"subdomain{'s' if len(subdomains) != 1 else ''} with issued SSL certs"
        )

        # ── Step 2: Probe for live services ──────────────────────────────────
        live_subdomains = []

        if self.probe and len(subdomains) <= 50:
            # Probe all discovered subdomains concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {
                    executor.submit(_probe_subdomain, sub): sub
                    for sub in subdomains
                }
                for future in concurrent.futures.as_completed(futures):
                    probe_result = future.result()
                    if probe_result:
                        live_subdomains.append(probe_result)

            result.passed.append(
                f"{len(live_subdomains)} of {len(subdomains)} subdomains are reachable "
                "over HTTP/HTTPS"
            )
        elif len(subdomains) > 50:
            # Too many to probe — just report the count
            result.passed.append(
                f"{len(subdomains)} subdomains found (too many to probe individually). "
                "Showing first 30."
            )
            subdomains = subdomains[:30]

        # ── Step 3: Flag interesting/suspicious subdomains ───────────────────
        suspicious_keywords = [
            "dev", "staging", "stage", "test", "qa", "uat", "sandbox",
            "demo", "beta", "alpha", "old", "legacy", "backup", "internal",
            "admin", "panel", "manage", "dashboard", "api", "vpn",
            "mail", "smtp", "ftp", "git", "jenkins", "jira", "confluence",
            "kibana", "grafana", "prometheus", "phpmyadmin",
        ]

        flagged = []
        for sub in subdomains:
            sub_prefix = sub.replace(f".{domain}", "").lower()
            for keyword in suspicious_keywords:
                if keyword in sub_prefix:
                    flagged.append((sub, keyword))
                    break

        # Report suspicious subdomains as findings
        if flagged:
            result.findings.append(Finding(
                title=f"Exposed Sensitive Subdomains: {len(flagged)} Found",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                description=(
                    f"Certificate Transparency logs reveal {len(flagged)} subdomain(s) "
                    "suggesting internal, development, or administrative services that "
                    "may have weaker security posture than the main domain:\n"
                    + "\n".join(f"  {sub} (keyword: {kw})" for sub, kw in flagged[:10])
                    + (f"\n  ... and {len(flagged)-10} more" if len(flagged) > 10 else "")
                ),
                recommendation=(
                    "1. Audit each sensitive subdomain for security misconfigurations\n"
                    "2. Restrict access to development/staging environments by IP\n"
                    "3. Remove unused subdomains and revoke their certificates\n"
                    "4. Do not expose admin panels, Jenkins, Kibana, or Grafana to the internet"
                ),
                evidence=f"Source: crt.sh Certificate Transparency search for *.{domain}"
            ))

        # Report live subdomains as informational
        if live_subdomains:
            live_list = ", ".join(s["subdomain"] for s in live_subdomains[:8])
            if len(live_subdomains) > 8:
                live_list += f" ... and {len(live_subdomains)-8} more"

            result.findings.append(Finding(
                title=f"Attack Surface: {len(live_subdomains)} Live Subdomains",
                severity=Severity.INFO,
                cvss_score=0.0,
                description=(
                    f"The following subdomains are actively serving HTTP/HTTPS traffic. "
                    "Each represents an independent attack surface that should be "
                    "individually assessed:\n" + live_list
                ),
                recommendation=(
                    "Run SentinelScan against each live subdomain individually "
                    "to check for security misconfigurations unique to each service."
                ),
                evidence=f"HTTP probe confirmed reachability. Source: crt.sh + live probe"
            ))

        # List all discovered subdomains in passed section
        for sub in subdomains[:15]:
            is_live = any(s["subdomain"] == sub for s in live_subdomains)
            status = "LIVE" if is_live else "no response"
            result.passed.append(f"  {sub} [{status}]")

        if len(subdomains) > 15:
            result.passed.append(f"  ... and {len(subdomains)-15} more (see JSON report)")

        return result
