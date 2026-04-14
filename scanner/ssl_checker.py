"""
SentinelScan - SSL/TLS Certificate Checker
============================================
Module 2: Analyzes the SSL/TLS configuration of a target.

Real-world importance:
  - Expired or weak SSL = browsers show scary "Not Secure" warnings
  - TLS 1.0 and 1.1 are deprecated and banned in PCI-DSS compliance
  - Companies can fail security audits for weak SSL alone
  - Microsoft Azure, AWS all REQUIRE TLS 1.2+ for all services

What this module checks:
  1. Is the certificate expired?
  2. How many days until expiry? (< 30 days = warning)
  3. Does the domain name match the certificate?
  4. Is the certificate self-signed (not from a trusted CA)?
  5. Does HTTP redirect to HTTPS?

Learning goals:
  - Python's ssl and socket standard library (no install needed!)
  - Working with datetime objects
  - Exception handling for different SSL error types
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

from scanner.models import Finding, ModuleResult, Severity


class SSLChecker:
    """
    Analyzes the SSL/TLS configuration of a target domain.

    Usage:
        checker = SSLChecker()
        result = checker.check("https://example.com")
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SentinelScan/1.0 Security Scanner (Authorized Use Only)"
        })

    def _extract_hostname(self, target: str) -> str:
        """Pull just the hostname from a full URL."""
        parsed = urlparse(target)
        return parsed.hostname or target

    def _get_certificate_info(self, hostname: str, port: int = 443) -> dict | None:
        """
        Connect to the server and retrieve its SSL certificate.

        This uses Python's built-in ssl + socket modules — no external library needed!
        This is how browsers verify certificates when you visit HTTPS sites.

        Returns:
            Dictionary of certificate fields, or None if connection failed
        """
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # get_peercert() returns the certificate as a dictionary
                    cert = ssock.getpeercert()
                    # Also get the TLS version being used
                    tls_version = ssock.version()
                    return {"cert": cert, "tls_version": tls_version}
        except ssl.SSLCertVerificationError as e:
            # Certificate is invalid/expired/self-signed
            return {"error": "verification_failed", "detail": str(e)}
        except ssl.SSLError as e:
            return {"error": "ssl_error", "detail": str(e)}
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return {"error": "connection_error", "detail": str(e)}

    def check(self, target: str) -> ModuleResult:
        """
        Run all SSL/TLS checks against the target.

        Args:
            target: Full URL (e.g., "https://example.com")

        Returns:
            ModuleResult with all SSL-related findings
        """
        result = ModuleResult(module_name="SSL/TLS Certificate", target=target)

        # ── CHECK 1: Is the site even using HTTPS? ───────────────────────
        if not target.startswith("https://"):
            result.findings.append(Finding(
                title="Target is not using HTTPS",
                severity=Severity.CRITICAL,
                cvss_score=9.1,
                description="Target URL uses HTTP, not HTTPS. No SSL/TLS encryption in use.",
                recommendation="Enable HTTPS. SSL certificates are free via Let's Encrypt.",
                evidence=f"URL: {target}"
            ))
            # Check if HTTPS redirect exists
            self._check_http_redirect(target, result)
            return result

        hostname = self._extract_hostname(target)
        cert_info = self._get_certificate_info(hostname)

        # ── HANDLE CONNECTION ERRORS ─────────────────────────────────────
        if cert_info is None:
            result.error = f"Could not retrieve certificate for {hostname}"
            return result

        if cert_info.get("error") == "verification_failed":
            result.findings.append(Finding(
                title="SSL Certificate Verification Failed",
                severity=Severity.CRITICAL,
                cvss_score=9.0,
                description=(
                    "The SSL certificate could not be verified. It may be:\n"
                    "  • Expired\n"
                    "  • Self-signed (not issued by a trusted Certificate Authority)\n"
                    "  • Issued for a different domain\n"
                    "Browsers will show a security warning to all users."
                ),
                recommendation=(
                    "Obtain a valid certificate from a trusted CA.\n"
                    "Free option: Let's Encrypt (https://letsencrypt.org)"
                ),
                evidence=cert_info.get("detail", "")[:200]
            ))
            return result

        if cert_info.get("error"):
            result.error = f"SSL error: {cert_info.get('detail', 'Unknown error')}"
            return result

        cert = cert_info["cert"]
        tls_version = cert_info.get("tls_version", "Unknown")

        # ── CHECK 2: Certificate expiry ──────────────────────────────────
        expiry_str = cert.get("notAfter", "")
        if expiry_str:
            # SSL cert dates are in format: "Apr 10 12:00:00 2025 GMT"
            expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)
            days_remaining = (expiry_date - datetime.now(timezone.utc)).days

            if days_remaining < 0:
                result.findings.append(Finding(
                    title="SSL Certificate EXPIRED",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    description=(
                        f"SSL certificate expired {abs(days_remaining)} days ago! "
                        "Browsers will block users from visiting this site. "
                        "All HTTPS connections are being rejected."
                    ),
                    recommendation="Renew the certificate immediately. Use Let's Encrypt for auto-renewal.",
                    evidence=f"Certificate expired on: {expiry_date.strftime('%Y-%m-%d')}"
                ))
            elif days_remaining <= 14:
                result.findings.append(Finding(
                    title=f"SSL Certificate Expiring Very Soon ({days_remaining} days)",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    description=(
                        f"SSL certificate expires in only {days_remaining} days. "
                        "When it expires, all users will see a security error."
                    ),
                    recommendation="Renew the certificate now before it expires.",
                    evidence=f"Certificate expires on: {expiry_date.strftime('%Y-%m-%d')}"
                ))
            elif days_remaining <= 30:
                result.findings.append(Finding(
                    title=f"SSL Certificate Expiring Soon ({days_remaining} days)",
                    severity=Severity.MEDIUM,
                    cvss_score=4.0,
                    description=f"SSL certificate expires in {days_remaining} days. Plan renewal soon.",
                    recommendation="Renew the certificate within the next two weeks.",
                    evidence=f"Certificate expires on: {expiry_date.strftime('%Y-%m-%d')}"
                ))
            else:
                result.passed.append(
                    f"Certificate valid — expires {expiry_date.strftime('%Y-%m-%d')} "
                    f"({days_remaining} days remaining)"
                )

        # ── CHECK 3: TLS Version ─────────────────────────────────────────
        # TLS 1.0 and 1.1 were officially deprecated (RFC 8996) in March 2021
        # PCI-DSS, HIPAA, and most enterprise security standards ban them
        if tls_version in ("TLSv1", "TLSv1.1"):
            result.findings.append(Finding(
                title=f"Deprecated TLS Version in Use: {tls_version}",
                severity=Severity.HIGH,
                cvss_score=7.5,
                description=(
                    f"The server negotiated {tls_version}, which is officially deprecated. "
                    "TLS 1.0 and 1.1 have known vulnerabilities (POODLE, BEAST) "
                    "and are banned by PCI-DSS, HIPAA, and GDPR compliance standards."
                ),
                recommendation=(
                    "Disable TLS 1.0 and 1.1 on your server. Enable TLS 1.2 and 1.3 only.\n"
                    "Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
                    "Nginx: ssl_protocols TLSv1.2 TLSv1.3;"
                ),
                evidence=f"Negotiated protocol: {tls_version}"
            ))
        elif tls_version == "TLSv1.2":
            result.passed.append(f"TLS 1.2 in use (acceptable — TLS 1.3 preferred)")
        elif tls_version == "TLSv1.3":
            result.passed.append(f"TLS 1.3 in use ✓ (best available)")
        else:
            result.passed.append(f"TLS version: {tls_version}")

        # ── CHECK 4: Certificate issuer (self-signed detection) ──────────
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer_org = issuer.get("organizationName", "Unknown")
        subject_org = subject.get("organizationName", "Unknown")

        if issuer_org == subject_org:
            result.findings.append(Finding(
                title="Potentially Self-Signed Certificate",
                severity=Severity.HIGH,
                cvss_score=7.4,
                description=(
                    "The certificate issuer matches the certificate subject — "
                    "this may indicate a self-signed certificate. "
                    "Browsers do not trust self-signed certificates and will warn all users."
                ),
                recommendation=(
                    "Replace with a certificate from a trusted CA "
                    "(e.g., DigiCert, Let's Encrypt, Sectigo)."
                ),
                evidence=f"Issuer: {issuer_org} | Subject: {subject_org}"
            ))
        else:
            result.passed.append(f"Certificate issued by: {issuer_org}")

        return result

    def _check_http_redirect(self, http_url: str, result: ModuleResult) -> None:
        """Check if the HTTP URL redirects to HTTPS."""
        try:
            resp = self.session.get(http_url, timeout=self.timeout, allow_redirects=False)
            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("Location", "")
                if location.startswith("https://"):
                    result.passed.append(f"HTTP redirects to HTTPS: {location[:60]}")
                    return
            result.findings.append(Finding(
                title="No HTTP → HTTPS Redirect",
                severity=Severity.HIGH,
                cvss_score=7.0,
                description=(
                    "No redirect from HTTP to HTTPS is configured. "
                    "Users who type the URL without 'https://' will use an unencrypted connection."
                ),
                recommendation="Configure a 301 redirect from all HTTP traffic to HTTPS.",
                evidence=f"HTTP {resp.status_code} — no redirect to HTTPS"
            ))
        except RequestException:
            pass  # If HTTP is completely broken, we've already flagged it above
