"""
SentinelScan - CORS Misconfiguration Checker
=============================================
Module 6: Tests Cross-Origin Resource Sharing (CORS) configuration
for misconfigurations that allow unauthorized cross-origin access.

Real-world importance:
  - Misconfigured CORS is one of the most common API security bugs
  - It allows malicious websites to make authenticated requests to your API
  - When combined with cookies or tokens, attackers can read private user data
  - Uber, PayPal, and many APIs have had CORS vulnerabilities in their history
  - Many developers add 'Access-Control-Allow-Origin: *' carelessly

How CORS works (important to understand):
  - Browser enforces "Same-Origin Policy" — scripts on evil.com CANNOT read
    responses from bank.com by default
  - CORS is a mechanism to RELAX same-origin policy in a controlled way
  - If a server says "Access-Control-Allow-Origin: *", it lets ANY website
    read the response via JavaScript — even if it contains private data
  - The dangerous combination is wildcard origin + credentials allowed

What this module tests:
  1. Wildcard CORS (allow all origins)
  2. Origin reflection (server mirrors back whatever Origin we send)
  3. Null origin acceptance
  4. Credentials + wildcard (the most dangerous combination)
  5. Pre-flight (OPTIONS) configuration

Learning goals:
  - How HTTP CORS headers work (important for any API developer)
  - Sending custom request headers
  - Understanding pre-flight requests
"""

import requests
from requests.exceptions import RequestException

from scanner.models import Finding, ModuleResult, Severity


# Origins we use to test different CORS scenarios
EVIL_ORIGIN = "https://evil-attacker.com"
NULL_ORIGIN = "null"
SUBDOMAIN_ORIGIN = "https://not-really-your-domain.trusted-site.com"


class CORSChecker:
    """
    Tests CORS configuration for common misconfigurations.

    CORS misconfigurations allow attackers to make cross-origin requests
    to your API from their own website and read the responses.

    Usage:
        checker = CORSChecker()
        result = checker.check("https://api.example.com")
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SentinelScan/1.0 Security Scanner (Authorized Use Only)"
        })

    def _request_with_origin(self, target: str, origin: str) -> requests.Response | None:
        """
        Send a request with a custom Origin header and return the response.

        The Origin header is what a browser sends to tell a server where
        the request is coming from. CORS decisions are made based on this.
        """
        try:
            response = self.session.get(
                target,
                headers={"Origin": origin},
                timeout=self.timeout,
                allow_redirects=True
            )
            return response
        except RequestException:
            return None

    def _preflight_request(self, target: str, origin: str) -> requests.Response | None:
        """
        Send a CORS pre-flight OPTIONS request.

        Pre-flight requests are sent by browsers before any cross-origin
        request that modifies data (PUT, DELETE, POST with JSON body).
        The server must respond correctly for the actual request to proceed.
        """
        try:
            response = self.session.options(
                target,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Content-Type, Authorization"
                },
                timeout=self.timeout
            )
            return response
        except RequestException:
            return None

    def check(self, target: str) -> ModuleResult:
        """
        Run all CORS misconfiguration checks.

        Args:
            target: URL to test (ideally an API endpoint)

        Returns:
            ModuleResult with all CORS findings
        """
        result = ModuleResult(module_name="CORS Misconfiguration", target=target)

        # ── TEST 1: Wildcard CORS ────────────────────────────────────────────
        # Access-Control-Allow-Origin: * means ANY website can read responses
        response = self._request_with_origin(target, EVIL_ORIGIN)
        if response is None:
            result.error = f"Could not connect to {target} for CORS testing"
            return result

        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*":
            # Wildcard by itself is OK for public APIs — but check for credentials
            if acac == "true":
                # This is a critical misconfiguration — browsers actually block this,
                # but it signals a fundamental misunderstanding of CORS
                result.findings.append(Finding(
                    title="CRITICAL CORS: Wildcard Origin + Credentials Allowed",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    description=(
                        "The server sets both 'Access-Control-Allow-Origin: *' AND "
                        "'Access-Control-Allow-Credentials: true'. "
                        "While browsers block this specific combination by spec, it indicates "
                        "a deep misunderstanding of CORS that likely exists elsewhere in the codebase. "
                        "If the wildcard is replaced with a reflected origin, this becomes a full "
                        "credential-leaking vulnerability immediately."
                    ),
                    recommendation=(
                        "Never combine wildcard CORS with credentials. "
                        "For authenticated endpoints: specify exact allowed origins, not wildcard.\n"
                        "Access-Control-Allow-Origin: https://yourdomain.com\n"
                        "Maintain an explicit whitelist of trusted origins."
                    ),
                    evidence=f"ACAO: {acao} | ACAC: {acac}"
                ))
            else:
                result.findings.append(Finding(
                    title="CORS: Wildcard Origin Allowed",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description=(
                        "'Access-Control-Allow-Origin: *' allows any website to read responses. "
                        "For truly public APIs this may be intentional. "
                        "However if any endpoint returns user-specific data (even with wildcard), "
                        "that data is readable by any malicious website the user visits."
                    ),
                    recommendation=(
                        "If this is a public API: document that all responses are public intentionally.\n"
                        "If any endpoint requires authentication or returns user data: "
                        "use an explicit origin whitelist instead of wildcard."
                    ),
                    evidence=f"Access-Control-Allow-Origin: {acao}"
                ))
        else:
            result.passed.append(f"No wildcard CORS — ACAO: {acao or '(not set)'}")

        # ── TEST 2: Origin Reflection ────────────────────────────────────────
        # Some servers blindly echo back whatever Origin header is sent.
        # This means ANY website the attacker controls gets full CORS access.
        if acao == EVIL_ORIGIN:
            result.findings.append(Finding(
                title="CORS: Server Reflects Arbitrary Origin",
                severity=Severity.HIGH if acac != "true" else Severity.CRITICAL,
                cvss_score=9.0 if acac == "true" else 7.5,
                description=(
                    "The server mirrors back any Origin header it receives. "
                    "An attacker at 'https://evil-attacker.com' can make cross-origin requests "
                    "to this server and read all responses — including authenticated data "
                    "if the victim's session cookies are included."
                    + (
                        " Credentials are explicitly allowed, making this immediately exploitable "
                        "to steal session tokens and private data." if acac == "true" else ""
                    )
                ),
                recommendation=(
                    "Implement an explicit origin whitelist. Validate the Origin header against "
                    "a list of known-good domains before reflecting it:\n"
                    "  ALLOWED = {'https://yourdomain.com', 'https://app.yourdomain.com'}\n"
                    "  if request.headers.get('Origin') in ALLOWED:\n"
                    "      response['Access-Control-Allow-Origin'] = request.headers['Origin']"
                ),
                evidence=f"Sent Origin: {EVIL_ORIGIN} | Received ACAO: {acao} | ACAC: {acac}"
            ))

        # ── TEST 3: Null Origin ──────────────────────────────────────────────
        # Some servers allow 'null' origin — triggered by sandboxed iframes,
        # data: URLs, and some redirect flows. Easily exploitable.
        null_response = self._request_with_origin(target, NULL_ORIGIN)
        if null_response:
            null_acao = null_response.headers.get("Access-Control-Allow-Origin", "")
            if null_acao == "null":
                result.findings.append(Finding(
                    title="CORS: Null Origin Accepted",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    description=(
                        "The server accepts 'null' as a valid origin. "
                        "Attackers can exploit this by hosting malicious content in a sandboxed iframe "
                        "(which sends null as the origin) to make cross-origin requests to this server "
                        "and read responses."
                    ),
                    recommendation=(
                        "Remove 'null' from your allowed origins list. "
                        "The null origin should never be granted CORS access."
                    ),
                    evidence="Sent Origin: null | Server responded with: Access-Control-Allow-Origin: null"
                ))
            else:
                result.passed.append("Null origin not accepted")

        # ── TEST 4: Pre-flight Configuration ────────────────────────────────
        preflight = self._preflight_request(target, EVIL_ORIGIN)
        if preflight:
            pf_acao = preflight.headers.get("Access-Control-Allow-Origin", "")
            pf_methods = preflight.headers.get("Access-Control-Allow-Methods", "")
            pf_headers = preflight.headers.get("Access-Control-Allow-Headers", "")

            if pf_acao == "*" or pf_acao == EVIL_ORIGIN:
                result.findings.append(Finding(
                    title="CORS: Pre-flight Allows Arbitrary Origin for Mutations",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    description=(
                        "The OPTIONS pre-flight response allows cross-origin requests for "
                        f"methods: {pf_methods or 'unspecified'}. "
                        "This allows attackers to make data-modifying requests (POST, PUT, DELETE) "
                        "from their own domain."
                    ),
                    recommendation=(
                        "Restrict CORS to specific, trusted origins in your pre-flight handler. "
                        "Endpoint: use framework-level CORS middleware with an explicit allowlist."
                    ),
                    evidence=f"Pre-flight ACAO: {pf_acao} | Methods: {pf_methods}"
                ))
            elif preflight.status_code in (200, 204):
                result.passed.append(
                    f"Pre-flight (OPTIONS) configured correctly — no arbitrary origin allowed"
                )

        # If no CORS headers at all, it might be fine (no cross-origin use)
        if not acao and not result.findings:
            result.passed.append(
                "No CORS headers present — cross-origin requests not enabled "
                "(acceptable if this is not an API consumed by other domains)"
            )

        return result
