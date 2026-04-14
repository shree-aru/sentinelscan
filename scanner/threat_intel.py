"""
SentinelScan - Threat Intelligence Module
==========================================
Module 7: Enrich scan results with real-world threat intelligence
using completely FREE, no-API-key-required public services.

Data sources used:
  1. Shodan InternetDB (internetdb.shodan.io)
     - No API key required, completely free
     - Returns: open ports, known CVEs, CPE strings, hostnames, tags
     - This is the same Shodan data that professional security teams pay for
     Used in: penetration testing, vulnerability management, threat hunting

  2. NVD (National Vulnerability Database) API — nvd.nist.gov
     - Maintained by NIST (US National Institute of Standards and Technology)
     - The authoritative source for CVE descriptions and CVSS scores
     - Free, no authentication required (rate limited to 5 req/30s without key)
     - Used to fetch human-readable descriptions of CVEs found by Shodan

Why this is powerful:
  - Instead of just detecting misconfigurations, SentinelScan now cross-
    references the target's open ports with the global CVE database
  - This is real threat intelligence — the kind Rapid7, Qualys, Tenable sell
  - A student project that pulls real CVE data is genuinely impressive

Real-world example output:
  "IP 104.21.234.56 has port 22 open. Shodan reports CVE-2023-38408
   (OpenSSH remote code execution, CVSS 9.8) is associated with this host."

Learning goals:
  - Working with JSON REST APIs (requests.get + .json())
  - DNS resolution with Python socket module
  - Rate limiting in API calls (time.sleep)
  - Data enrichment pattern — combining multiple data sources
"""

import socket
import time
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

from scanner.models import Finding, ModuleResult, Severity


# Base URLs for free APIs
SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _resolve_hostname(hostname: str) -> str | None:
    """
    Resolve a hostname to its IP address using DNS.

    socket.gethostbyname() is Python's built-in DNS resolver.
    All internet communication ultimately uses IPs, not hostnames.

    Returns:
        IP address string, or None if resolution fails
    """
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        return None


def _fetch_shodan_data(ip: str) -> dict | None:
    """
    Query Shodan InternetDB for a given IP address.

    InternetDB is Shodan's free, no-auth API that exposes pre-crawled
    data for any public IP. It's updated continuously by Shodan's global
    scanning infrastructure.

    Args:
        ip: IPv4 address string

    Returns:
        Dict with keys: cpes, hostnames, ip, ports, tags, vulns
        Or None if no data exists / request failed
    """
    try:
        url = SHODAN_INTERNETDB_URL.format(ip=ip)
        response = requests.get(url, timeout=8)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return None  # No data for this IP (common for CDN IPs)
        else:
            return None

    except RequestException:
        return None


def _fetch_cve_description(cve_id: str) -> dict | None:
    """
    Fetch CVE details from the NVD (National Vulnerability Database).

    Returns a dict with description and CVSS score, or None on failure.
    NVD rate-limits unauthenticated requests to 5 per 30 seconds.
    We add a small delay between calls to be respectful.
    """
    try:
        params = {"cveId": cve_id}
        response = requests.get(NVD_CVE_URL, params=params, timeout=10)

        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                return None

            cve_data = vulnerabilities[0].get("cve", {})
            descriptions = cve_data.get("descriptions", [])

            # Get English description
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Get CVSS score
            metrics = cve_data.get("metrics", {})
            cvss_score = 0.0
            cvss_severity = "UNKNOWN"

            # Try CVSS 3.1 first, then 3.0, then 2.0
            for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if version_key in metrics and metrics[version_key]:
                    metric = metrics[version_key][0]
                    cvss_data = metric.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    cvss_severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    break

            return {
                "description": description[:400],  # Truncate for display
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity
            }

    except RequestException:
        return None

    return None


def _cvss_to_severity(cvss_score: float) -> Severity:
    """Map a CVSS numeric score to our internal Severity enum."""
    if cvss_score >= 9.0:
        return Severity.CRITICAL
    elif cvss_score >= 7.0:
        return Severity.HIGH
    elif cvss_score >= 4.0:
        return Severity.MEDIUM
    elif cvss_score > 0:
        return Severity.LOW
    else:
        return Severity.INFO


class ThreatIntelModule:
    """
    Enriches scan results with threat intelligence from Shodan and NVD.

    This module:
      1. Resolves the target hostname to an IP
      2. Queries Shodan InternetDB for known CVEs, open ports, and CPEs
      3. For each CVE found, fetches the description from NVD
      4. Creates findings with real CVE data and CVSS scores

    This is what separates SentinelScan from basic header scanners.

    Usage:
        intel = ThreatIntelModule()
        result = intel.check("https://example.com")
    """

    def __init__(self, max_cve_lookups: int = 5):
        """
        Args:
            max_cve_lookups: Maximum number of CVEs to look up on NVD
                             (keeps the scan fast — NVD is rate-limited)
        """
        self.max_cve_lookups = max_cve_lookups

    def check(self, target: str) -> ModuleResult:
        """
        Run threat intelligence enrichment for the target.

        Args:
            target: Full URL of the scan target

        Returns:
            ModuleResult with CVE-based findings and open port information
        """
        result = ModuleResult(module_name="Threat Intelligence (Shodan + NVD)", target=target)

        # ── Step 1: Resolve hostname to IP ───────────────────────────────────
        parsed = urlparse(target)
        hostname = parsed.hostname or target

        ip = _resolve_hostname(hostname)
        if not ip:
            result.error = f"Could not resolve hostname '{hostname}' to an IP address"
            return result

        result.passed.append(f"Resolved {hostname} -> {ip}")

        # ── Step 2: Query Shodan InternetDB ──────────────────────────────────
        shodan_data = _fetch_shodan_data(ip)

        if shodan_data is None:
            result.passed.append(
                f"No Shodan data available for {ip} "
                "(common for CDN IPs like Cloudflare — the real server IP is hidden)"
            )
            return result

        # ── Step 3: Report open ports ────────────────────────────────────────
        open_ports = shodan_data.get("ports", [])
        if open_ports:
            # Flag potentially dangerous ports
            dangerous_ports = {
                21: ("FTP", "transmits data in plaintext"),
                23: ("Telnet", "unencrypted remote access — should never be internet-facing"),
                3306: ("MySQL", "database port exposed to internet"),
                5432: ("PostgreSQL", "database port exposed to internet"),
                6379: ("Redis", "often unauthenticated by default"),
                27017: ("MongoDB", "often unauthenticated by default"),
                9200: ("Elasticsearch", "often unauthenticated by default"),
                5900: ("VNC", "remote desktop protocol — high risk if exposed"),
                3389: ("RDP", "Windows Remote Desktop — major attack surface"),
                445: ("SMB", "Windows file sharing — EternalBlue exploited this"),
                8080: ("HTTP Alt", "development server exposed to internet"),
                8443: ("HTTPS Alt", "alternative HTTPS — verify it's intentional"),
            }

            for port in open_ports:
                if port in dangerous_ports:
                    service, reason = dangerous_ports[port]
                    result.findings.append(Finding(
                        title=f"Dangerous Port Exposed: {port}/{service}",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        description=(
                            f"Port {port} ({service}) is open and internet-facing. "
                            f"Risk: {reason}. "
                            "Exposing internal services to the internet dramatically increases "
                            "the attack surface — these ports should be behind a firewall or VPN."
                        ),
                        recommendation=(
                            f"If {service} is needed internally, restrict access with a firewall rule "
                            f"allowing only trusted IP ranges. Never expose {service} to 0.0.0.0."
                        ),
                        evidence=f"Shodan InternetDB reports port {port} open on {ip}"
                    ))

            result.passed.append(
                f"Open ports detected by Shodan: {', '.join(str(p) for p in sorted(open_ports))}"
            )

        # ── Step 4: Technology fingerprinting from CPEs ──────────────────────
        cpes = shodan_data.get("cpes", [])
        if cpes:
            result.passed.append(
                f"Technology fingerprint (CPEs): {' | '.join(cpes[:5])}"
            )

        # ── Step 5: Process known CVEs ───────────────────────────────────────
        known_vulns = shodan_data.get("vulns", [])

        if not known_vulns:
            result.passed.append(
                f"Shodan reports no known CVEs currently associated with {ip}"
            )
        else:
            result.findings.append(Finding(
                title=f"Shodan Reports {len(known_vulns)} Known CVE(s) on This Host",
                severity=Severity.HIGH,
                cvss_score=7.0,
                description=(
                    f"Shodan InternetDB has associated the following CVEs with IP {ip}: "
                    f"{', '.join(known_vulns[:10])}{'...' if len(known_vulns) > 10 else ''}. "
                    "These are vulnerabilities in services running on this server that Shodan's "
                    "global scanners have identified. They require immediate investigation."
                ),
                recommendation=(
                    "1. Verify each CVE applies to your specific software version\n"
                    "2. Check vendor advisories and patch immediately if applicable\n"
                    "3. Use NVD (nvd.nist.gov) to view full CVE details\n"
                    "4. Subscribe to security mailing lists for your technology stack"
                ),
                evidence=f"Source: Shodan InternetDB for IP {ip}"
            ))

            # Fetch detailed descriptions for top CVEs from NVD
            lookups = min(self.max_cve_lookups, len(known_vulns))

            for cve_id in known_vulns[:lookups]:
                # Rate limit: NVD allows 5 requests per 30 seconds without an API key
                time.sleep(0.7)

                cve_detail = _fetch_cve_description(cve_id)

                if cve_detail and cve_detail.get("description"):
                    severity = _cvss_to_severity(cve_detail["cvss_score"])
                    result.findings.append(Finding(
                        title=f"{cve_id} — {cve_detail['cvss_severity']} (CVSS {cve_detail['cvss_score']})",
                        severity=severity,
                        cvss_score=cve_detail["cvss_score"],
                        description=cve_detail["description"],
                        recommendation=(
                            f"Review {cve_id} at: https://nvd.nist.gov/vuln/detail/{cve_id}\n"
                            "Apply the vendor patch or upgrade to a version that addresses this CVE."
                        ),
                        evidence=f"Reported by Shodan for {ip} | Verified via NVD"
                    ))

        # ── Step 6: Tags from Shodan ─────────────────────────────────────────
        tags = shodan_data.get("tags", [])
        if tags:
            tag_str = ", ".join(tags)

            if "self-signed" in tags:
                result.findings.append(Finding(
                    title="Shodan Tag: Self-Signed Certificate Detected",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description=(
                        "Shodan has tagged this host as using a self-signed SSL certificate. "
                        "Self-signed certificates are not trusted by browsers and indicate "
                        "the server may not be properly configured for production use."
                    ),
                    recommendation="Replace the self-signed certificate with one from a trusted CA.",
                    evidence=f"Shodan tags for {ip}: {tag_str}"
                ))

            if "vpn" in tags:
                result.passed.append(f"Shodan identifies this host as a VPN endpoint (tags: {tag_str})")
            elif tags:
                result.passed.append(f"Shodan tags for {ip}: {tag_str}")

        return result
