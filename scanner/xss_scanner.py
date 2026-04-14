"""
SentinelScan - Reflected XSS Scanner
=======================================
Module 5: Tests URL parameters and form inputs for reflected
Cross-Site Scripting (XSS) vulnerabilities.

Real-world importance:
  - XSS is OWASP Top 3 (A03:2021 Injection)
  - Reflected XSS lets attackers steal cookies, session tokens, credentials
  - Used in phishing: attacker sends victim a crafted URL to your trusted domain
  - British Airways, Magecart used XSS to skim credit card data in real-time
  - Even Google and Facebook have paid bug bounties for XSS findings

Types of XSS this module detects:
  - REFLECTED XSS: payload is sent in a request and immediately returned in the
    response without being stored. Classic attack vector via malicious links.

Types NOT covered here (planned for v2):
  - Stored XSS: payload is saved to a database and served to all users
  - DOM-based XSS: payload executes via JavaScript in the browser (requires a
    headless browser like Playwright to detect properly)

Learning goals:
  - HTML context analysis (raw reflection vs. attribute vs. JS context)
  - Why string matching matters more than just payload reflection
  - urllib.parse for building test URLs
"""

import copy
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List

import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

from scanner.models import Finding, ModuleResult, Severity


# ─────────────────────────────────────────────────────────────────────────────
#  XSS PAYLOADS
#  Each payload attempts to inject into a different HTML context.
#  We use a unique marker (xss_sentinel_RANDOMID) so we can precisely
#  locate our reflection in the response — avoiding false positives.
# ─────────────────────────────────────────────────────────────────────────────

# Unique marker embedded in every payload so we can find our reflection
MARKER = "xss7sentinel"

XSS_PAYLOADS = [
    # HTML context — basic script injection
    f"<script>alert('{MARKER}')</script>",
    # Attribute context break-out
    f'"><script>alert("{MARKER}")</script>',
    f"'><script>alert('{MARKER}')</script>",
    # Event handler injection
    f'" onmouseover="alert(\'{MARKER}\')" x="',
    f"' onfocus='alert('{MARKER}')' autofocus='",
    # img tag with onerror
    f"<img src=x onerror=alert('{MARKER}')>",
    f'"><img src=x onerror=alert("{MARKER}")>',
    # SVG injection
    f"<svg onload=alert('{MARKER}')>",
    # JavaScript URI
    f"javascript:alert('{MARKER}')",
]

# ─────────────────────────────────────────────────────────────────────────────
#  REFLECTION SEVERITY LEVELS
#  Finding our payload in a raw HTML context is the most dangerous.
#  Finding it inside a comment or encoded is lower risk.
# ─────────────────────────────────────────────────────────────────────────────

def _assess_reflection_severity(payload: str, response_text: str) -> tuple:
    """
    Determine how dangerous the XSS reflection is based on context.

    Returns (Severity, explanation, cvss_score)
    """
    # Most dangerous: script tags are reflected unencoded
    if f"<script>alert('{MARKER}')</script>" in response_text:
        return (
            Severity.CRITICAL,
            "Script tag reflected unencoded — payload will execute directly in browser",
            9.3
        )

    # High: event handlers or img tags reflected
    if f"onerror=alert('{MARKER}')" in response_text or f"onmouseover=alert" in response_text:
        return (
            Severity.HIGH,
            "Event handler payload reflected — likely executable in browser",
            8.1
        )

    # Medium: payload reflected without angle brackets encoded
    if MARKER in response_text and "<" in response_text:
        return (
            Severity.HIGH,
            "Payload partially reflected with unencoded angle brackets",
            7.4
        )

    # Lower: marker reflected but angle brackets might be encoded
    if MARKER in response_text:
        return (
            Severity.MEDIUM,
            "Payload marker reflected — value not properly sanitized but may be HTML-encoded",
            5.4
        )

    return (Severity.INFO, "", 0.0)


class XSSScanner:
    """
    Tests for reflected XSS vulnerabilities in URL parameters and form inputs.

    Strategy:
      - Inject each payload into a parameter
      - Check if the payload (or our unique marker) appears in the response body
      - Assess the context of the reflection to determine severity

    Usage:
        scanner = XSSScanner()
        result = scanner.check("https://example.com/search?q=hello")
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SentinelScan/1.0 Security Scanner (Authorized Use Only)"
        })

    def _test_get_params(self, target: str, result: ModuleResult) -> None:
        """Test GET parameters in URL for reflected XSS."""
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return

        for param_name, original_values in params.items():
            for payload in XSS_PAYLOADS:
                test_params = copy.deepcopy(params)
                test_params[param_name] = [payload]

                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    response = self.session.get(
                        test_url,
                        timeout=self.timeout,
                        allow_redirects=True
                    )

                    severity, context_desc, cvss = _assess_reflection_severity(
                        payload, response.text
                    )

                    if severity != Severity.INFO:
                        result.findings.append(Finding(
                            title=f"Reflected XSS — GET parameter: '{param_name}'",
                            severity=severity,
                            cvss_score=cvss,
                            description=(
                                f"The GET parameter '{param_name}' reflects user input back into the "
                                "HTML response without proper encoding. An attacker can craft a malicious "
                                "URL and send it to victims. When clicked, the script executes in the "
                                "victim's browser — stealing session cookies, redirecting to phishing pages, "
                                "or performing actions on behalf of the victim.\n"
                                f"Context: {context_desc}"
                            ),
                            recommendation=(
                                "HTML-encode all user-supplied data before inserting it into HTML responses.\n"
                                "Use context-aware encoding:\n"
                                "  HTML body:       htmlspecialchars($input, ENT_QUOTES)\n"
                                "  HTML attribute:  use attribute encoding\n"
                                "  JavaScript:      JSON.stringify() or JS-encode values\n"
                                "Implement a Content-Security-Policy header to limit script execution sources.\n"
                                "Use a templating engine that auto-escapes by default (Jinja2, Django templates)."
                            ),
                            evidence=f"Payload: {payload[:80]}  | Parameter: {param_name}"
                        ))
                        break  # Confirmed vuln on this param, move on

                except RequestException:
                    continue

    def _extract_forms(self, target: str) -> List[dict]:
        """Parse the target page and return all HTML forms with their inputs."""
        forms = []
        try:
            response = self.session.get(target, timeout=self.timeout)
            soup = BeautifulSoup(response.text, "html.parser")

            for form in soup.find_all("form"):
                parsed = urlparse(target)
                base = f"{parsed.scheme}://{parsed.netloc}"
                action = form.get("action", target)
                if action and not action.startswith("http"):
                    action = base + action
                elif not action:
                    action = target

                form_data = {
                    "action": action,
                    "method": form.get("method", "get").lower(),
                    "inputs": {}
                }
                for inp in form.find_all(["input", "textarea"]):
                    name = inp.get("name")
                    if name:
                        inp_type = inp.get("type", "text").lower()
                        if inp_type not in ("submit", "checkbox", "radio", "hidden", "file"):
                            form_data["inputs"][name] = "test"

                if form_data["inputs"]:
                    forms.append(form_data)

        except RequestException:
            pass

        return forms

    def _test_forms(self, target: str, result: ModuleResult) -> None:
        """Test HTML form inputs for reflected XSS."""
        for form in self._extract_forms(target):
            for param_name in form["inputs"]:
                for payload in XSS_PAYLOADS[:5]:
                    test_data = copy.deepcopy(form["inputs"])
                    test_data[param_name] = payload

                    try:
                        if form["method"] == "post":
                            response = self.session.post(
                                form["action"],
                                data=test_data,
                                timeout=self.timeout
                            )
                        else:
                            response = self.session.get(
                                form["action"],
                                params=test_data,
                                timeout=self.timeout
                            )

                        severity, context_desc, cvss = _assess_reflection_severity(
                            payload, response.text
                        )

                        if severity != Severity.INFO:
                            result.findings.append(Finding(
                                title=f"Reflected XSS — Form field: '{param_name}' ({form['method'].upper()})",
                                severity=severity,
                                cvss_score=cvss,
                                description=(
                                    f"Form field '{param_name}' at {form['action']} reflects "
                                    "unsanitized input into the HTML response.\n"
                                    f"Context: {context_desc}"
                                ),
                                recommendation=(
                                    "Apply HTML output encoding to all form data before rendering it. "
                                    "Use framework-level auto-escaping and add a strong CSP header."
                                ),
                                evidence=f"Payload: {payload[:80]} | Field: {param_name}"
                            ))
                            break

                    except RequestException:
                        continue

    def check(self, target: str) -> ModuleResult:
        """Run all XSS checks against the target."""
        result = ModuleResult(module_name="Reflected XSS", target=target)

        self._test_get_params(target, result)
        self._test_forms(target, result)

        if not result.findings:
            result.passed.append(
                "No reflected XSS detected in URL parameters or discovered form inputs "
                "(stored XSS and DOM-based XSS require separate testing)"
            )

        return result
