"""
SentinelScan - Security Headers Checker
=========================================
Module 1: Analyzes HTTP response headers for missing/misconfigured
security headers that protect against XSS, clickjacking, and more.

Real-world importance:
  - Missing security headers are in OWASP Top 10 (A05: Security Misconfiguration)
  - Companies like Microsoft, Google, and Meta enforce ALL these headers
  - A missing CSP header is enough for a hacker to steal all user data

Learning goals in this file:
  - Python dataclasses and type hints
  - HTTP requests with the requests library
  - Structured error handling (try/except)
  - Dictionary-driven configuration (vs hard-coded if/else chains)
"""

import requests
from requests.exceptions import SSLError, ConnectionError, Timeout, RequestException

from scanner.models import Finding, ModuleResult, Severity


# ─────────────────────────────────────────────────────────
#  SECURITY HEADERS KNOWLEDGE BASE
#  Dictionary-driven config: adding a new header to check
#  only requires adding one entry here. No code changes needed.
# ─────────────────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "cvss": 7.4,
        "description": (
            "HSTS (HTTP Strict Transport Security) header is missing. "
            "Without HSTS, attackers on the same network can perform "
            "SSL stripping attacks — downgrading HTTPS connections to "
            "insecure HTTP and intercepting all traffic."
        ),
        "recommendation": (
            "Add this header to your server config:\n"
            "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
            "The 'preload' flag submits your site to browsers' built-in HSTS list."
        ),
    },
    "Content-Security-Policy": {
        "severity": Severity.HIGH,
        "cvss": 6.1,
        "description": (
            "CSP (Content Security Policy) header is missing. "
            "CSP is your primary defense against Cross-Site Scripting (XSS) attacks. "
            "Without it, an attacker who injects any script into your page "
            "can steal cookies, tokens, and user data — or redirect users to phishing sites."
        ),
        "recommendation": (
            "Start with a basic CSP and tighten it over time:\n"
            "  Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'"
        ),
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "cvss": 4.3,
        "description": (
            "X-Frame-Options header is missing. "
            "Without this, attackers can embed your site inside a hidden iframe "
            "and trick users into clicking invisible buttons (clickjacking). "
            "This was used to steal Facebook likes, Twitter follows, and banking approvals."
        ),
        "recommendation": (
            "Add: X-Frame-Options: DENY\n"
            "Or if you need same-origin frames: X-Frame-Options: SAMEORIGIN"
        ),
    },
    "X-Content-Type-Options": {
        "severity": Severity.MEDIUM,
        "cvss": 3.7,
        "description": (
            "X-Content-Type-Options: nosniff is missing. "
            "Browsers may 'MIME-sniff' responses and treat a text file as executable JavaScript. "
            "If an attacker uploads a file with hidden script content, the browser could run it."
        ),
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "cvss": 3.1,
        "description": (
            "Referrer-Policy header is missing. "
            "When users click links leaving your site, the browser sends the full URL "
            "as the Referer header — potentially leaking sensitive URL parameters "
            "(like /reset-password?token=abc123) to third-party sites."
        ),
        "recommendation": (
            "Add: Referrer-Policy: strict-origin-when-cross-origin\n"
            "This sends only the origin (not full URL) for cross-origin requests."
        ),
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "cvss": 2.5,
        "description": (
            "Permissions-Policy header is missing. "
            "This header controls which browser features (camera, microphone, "
            "geolocation, payment) embedded scripts and iframes can access. "
            "Without it, third-party scripts on your page could silently access hardware."
        ),
        "recommendation": (
            "Add: Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()\n"
            "Only allow features your site actually uses."
        ),
    },
}

# Headers that SHOULD NOT be present (they leak information)
LEAKY_HEADERS = {
    "Server": {
        "severity": Severity.LOW,
        "cvss": 2.0,
        "description": (
            "The Server header reveals your web server software and version (e.g., Apache/2.4.41). "
            "Attackers can query CVE databases for known exploits targeting that exact version."
        ),
        "recommendation": (
            "Configure your server to return a generic value:\n"
            "Apache: ServerTokens Prod\n"
            "Nginx: server_tokens off;"
        ),
    },
    "X-Powered-By": {
        "severity": Severity.LOW,
        "cvss": 2.0,
        "description": (
            "X-Powered-By header reveals your backend technology (e.g., PHP/7.4.3, Express). "
            "This information helps attackers narrow down which exploits to try."
        ),
        "recommendation": (
            "Remove this header entirely:\n"
            "PHP: expose_php = Off  (in php.ini)\n"
            "Express.js: app.disable('x-powered-by')"
        ),
    },
    "X-AspNet-Version": {
        "severity": Severity.LOW,
        "cvss": 2.0,
        "description": "X-AspNet-Version exposes your exact ASP.NET version to attackers.",
        "recommendation": "Disable in web.config: <httpRuntime enableVersionHeader='false'/>",
    },
}


class HeaderChecker:
    """
    Checks HTTP response headers for security misconfigurations.

    Usage:
        checker = HeaderChecker()
        result = checker.check("https://example.com")
        print(result.findings)  # List of vulnerabilities found
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        # Use a session for efficient connection reuse
        self.session = requests.Session()
        # Identify ourselves honestly — ethical scanners do this
        self.session.headers.update({
            "User-Agent": "SentinelScan/1.0 Security Scanner (Authorized Use Only)"
        })

    def check(self, target: str) -> ModuleResult:
        """
        Run all header checks against the target URL.

        Args:
            target: Full URL to scan (e.g., "https://example.com")

        Returns:
            ModuleResult containing all findings and passed checks
        """
        result = ModuleResult(module_name="Security Headers", target=target)

        try:
            # Follow redirects (HTTP → HTTPS) to check final destination
            response = self.session.get(
                target,
                timeout=self.timeout,
                allow_redirects=True,
                verify=True  # Always verify SSL certificates
            )

            # Normalize header names to lowercase for case-insensitive comparison
            # HTTP headers are case-insensitive per RFC 7230
            response_headers = {k.lower(): v for k, v in response.headers.items()}

            # ── CHECK 1: Required security headers ──────────────────────
            for header_name, details in SECURITY_HEADERS.items():
                if header_name.lower() not in response_headers:
                    result.findings.append(Finding(
                        title=f"Missing Header: {header_name}",
                        severity=details["severity"],
                        cvss_score=details["cvss"],
                        description=details["description"],
                        recommendation=details["recommendation"],
                        evidence=f"Header '{header_name}' not present in response"
                    ))
                else:
                    header_value = response_headers[header_name.lower()]
                    result.passed.append(f"{header_name}: {header_value[:80]}")

            # ── CHECK 2: Headers that should NOT be present ─────────────
            for header_name, details in LEAKY_HEADERS.items():
                if header_name.lower() in response_headers:
                    leaked_value = response_headers[header_name.lower()]
                    result.findings.append(Finding(
                        title=f"Information Disclosure: {header_name}",
                        severity=details["severity"],
                        cvss_score=details["cvss"],
                        description=details["description"],
                        recommendation=details["recommendation"],
                        evidence=f"Observed: {header_name}: {leaked_value}"
                    ))

            # ── CHECK 3: Weak CSP detection ──────────────────────────────
            # Even if CSP exists, some configurations are dangerously weak
            if "content-security-policy" in response_headers:
                csp_value = response_headers["content-security-policy"].lower()
                if "'unsafe-inline'" in csp_value or "'unsafe-eval'" in csp_value:
                    result.findings.append(Finding(
                        title="Weak Content-Security-Policy (unsafe directives)",
                        severity=Severity.MEDIUM,
                        cvss_score=5.4,
                        description=(
                            "CSP header is present but uses 'unsafe-inline' or 'unsafe-eval' directives. "
                            "These effectively disable most CSP protections against XSS."
                        ),
                        recommendation=(
                            "Remove 'unsafe-inline' and 'unsafe-eval' from your CSP. "
                            "Use nonces or hashes for inline scripts instead."
                        ),
                        evidence=f"CSP: {response_headers['content-security-policy'][:120]}"
                    ))

            # ── CHECK 4: HTTP (not HTTPS) usage ─────────────────────────
            if target.startswith("http://"):
                result.findings.append(Finding(
                    title="No HTTPS — Unencrypted Connection",
                    severity=Severity.CRITICAL,
                    cvss_score=9.1,
                    description=(
                        "The target is using plain HTTP, not HTTPS. "
                        "All data (passwords, cookies, form inputs) is transmitted in plaintext "
                        "and can be intercepted by anyone on the network (man-in-the-middle attack)."
                    ),
                    recommendation=(
                        "1. Obtain a free SSL certificate from Let's Encrypt\n"
                        "2. Configure your server to redirect all HTTP traffic to HTTPS\n"
                        "3. Add the HSTS header to prevent future HTTP connections"
                    ),
                    evidence="URL scheme is 'http://' — no TLS encryption"
                ))

        # ── GRACEFUL ERROR HANDLING ──────────────────────────────────────
        except SSLError as e:
            result.findings.append(Finding(
                title="SSL Certificate Error",
                severity=Severity.CRITICAL,
                cvss_score=9.0,
                description=(
                    "Could not establish a secure connection. "
                    "The SSL/TLS certificate is invalid, expired, or self-signed."
                ),
                recommendation="Obtain and install a valid SSL certificate (Let's Encrypt is free).",
                evidence=str(e)[:200]
            ))
        except ConnectionError:
            result.error = f"Could not connect to {target}. Host may be unreachable or URL is incorrect."
        except Timeout:
            result.error = f"Connection to {target} timed out after {self.timeout} seconds."
        except RequestException as e:
            result.error = f"Unexpected error while scanning {target}: {str(e)[:100]}"

        return result
