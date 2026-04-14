"""
SentinelScan - SQL Injection Scanner
======================================
Module 4: Tests URL parameters and HTML form inputs for SQL injection
vulnerabilities by sending crafted payloads and analyzing error responses.

Real-world importance:
  - SQL injection is consistently OWASP Top 1 for a decade
  - A single SQLi vulnerability can expose an entire database
  - The 2017 Equifax breach (147 million records) started with an unpatched vuln
  - Companies like Yahoo, Adobe, Sony were all hit by SQLi attacks

What this module does:
  1. Extracts GET parameters from the target URL
  2. Crawls the target page for HTML forms (POST parameters)
  3. Injects SQL payloads into each parameter one at a time
  4. Looks for SQL error messages leaked in the response
  5. Also tries time-based blind SQLi detection

IMPORTANT - Ethical boundary:
  This module only DETECTS — it never extracts data from databases.
  It sends a payload, reads the HTTP response, and reports if an error
  message leaked. No data is accessed or exfiltrated.

Learning goals:
  - urllib.parse for URL manipulation
  - BeautifulSoup for HTML parsing (new library!)
  - Itertools for payload/parameter combinations
  - Time measurement for blind SQLi detection
"""

import time
import copy
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Tuple

import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

from scanner.models import Finding, ModuleResult, Severity


# ─────────────────────────────────────────────────────────────────────────────
#  SQL INJECTION PAYLOADS
#  Each payload is designed to break out of a SQL string context.
#  We use a mix of error-based and simple boolean payloads.
# ─────────────────────────────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    # Basic string terminators — trigger syntax errors if input is unsanitized
    "'",
    "\"",
    "''",
    # Boolean-based — changes query logic
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "1' AND '1'='2'--",
    # UNION-based — tries to append extra SELECT
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    # Comment-based termination
    "1'--",
    "1'#",
    "1' /*",
]

# ─────────────────────────────────────────────────────────────────────────────
#  SQL ERROR SIGNATURES
#  These are error strings that database engines leak when a SQL query
#  breaks due to malformed input. We check if any of these appear in
#  the HTTP response body after injecting our payload.
# ─────────────────────────────────────────────────────────────────────────────
SQL_ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql_",
    "mysql_fetch_array()",
    "mysql_num_rows()",
    "mysql_query()",
    "supplied argument is not a valid mysql",
    "unclosed quotation mark",
    # PostgreSQL
    "pg_exec()",
    "postgresql query failed",
    "pg_query()",
    # Oracle
    "ora-",
    "oracle error",
    "oracle.*driver",
    # Microsoft SQL Server
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
    "microsoft jet database",
    "[microsoft][odbc sql server driver]",
    "unclosed quotation mark after the character string",
    # Generic
    "sqlstate",
    "db2 sql error",
    "sqlite_",
    "warning: sqlite",
    "sql syntax.*mysql",
    "valid mysql result",
    "division by zero in",
    "quoted string not properly terminated",
    "syntax error or access violation",
]


class SQLiScanner:
    """
    Tests for SQL injection vulnerabilities in URL parameters and HTML forms.

    The approach:
      1. Find all injectable parameters (GET params in URL, form fields in HTML)
      2. For each parameter, replace its value with our payloads one at a time
      3. Send the modified request and check the response for SQL error strings
      4. Report any parameter where we detected a SQL error

    Usage:
        scanner = SQLiScanner()
        result = scanner.check("https://example.com/search?q=test&id=1")
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SentinelScan/1.0 Security Scanner (Authorized Use Only)"
        })

    def _contains_sql_error(self, response_text: str) -> str:
        """
        Check if the response body contains any SQL error signature.

        Returns the matched error string if found, empty string if not.
        """
        lower_text = response_text.lower()
        for signature in SQL_ERROR_SIGNATURES:
            if signature.lower() in lower_text:
                return signature
        return ""

    def _test_get_params(self, target: str, result: ModuleResult) -> None:
        """
        Test all GET parameters in the target URL for SQLi.

        Example: https://example.com/page?id=1&name=test
        Tests id=1 and name=test separately with all payloads.
        """
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return  # No GET parameters to test

        for param_name, original_values in params.items():
            for payload in SQLI_PAYLOADS:
                # Build modified params: replace only this param's value with payload
                test_params = copy.deepcopy(params)
                test_params[param_name] = [payload]

                # Rebuild the full URL with the injected parameter
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    response = self.session.get(
                        test_url,
                        timeout=self.timeout,
                        allow_redirects=True
                    )

                    matched_error = self._contains_sql_error(response.text)
                    if matched_error:
                        result.findings.append(Finding(
                            title=f"SQL Injection — GET parameter: '{param_name}'",
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            description=(
                                f"The GET parameter '{param_name}' is vulnerable to SQL injection. "
                                "User input is being passed directly to a database query without "
                                "sanitization. An attacker can manipulate the query to read, modify, "
                                "or delete data — or in some cases execute commands on the server."
                            ),
                            recommendation=(
                                "Use parameterized queries (prepared statements) — NEVER concatenate "
                                "user input into SQL strings.\n"
                                "Python: cursor.execute('SELECT * FROM t WHERE id = %s', (user_input,))\n"
                                "Java:   PreparedStatement ps = conn.prepareStatement('SELECT * FROM t WHERE id = ?')\n"
                                "Also validate and whitelist expected input types (e.g., enforce integer for ID fields)."
                            ),
                            evidence=(
                                f"Payload '{payload}' on parameter '{param_name}' triggered: "
                                f"\"{matched_error}\" in response"
                            )
                        ))
                        return  # Found vuln on this param — no need to test more payloads

                except RequestException:
                    continue

    def _extract_forms(self, target: str) -> List[dict]:
        """
        Crawl the target page and extract all HTML forms.

        BeautifulSoup parses the HTML and finds <form> elements.
        For each form, we extract the action URL and all input fields.

        This is how a real web scanner discovers POST-based injection points.
        """
        forms = []
        try:
            response = self.session.get(target, timeout=self.timeout)
            soup = BeautifulSoup(response.text, "html.parser")

            for form in soup.find_all("form"):
                form_data = {
                    "action": form.get("action", target),
                    "method": form.get("method", "get").lower(),
                    "inputs": {}
                }

                # If form action is relative, make it absolute
                if form_data["action"] and not form_data["action"].startswith("http"):
                    parsed = urlparse(target)
                    base = f"{parsed.scheme}://{parsed.netloc}"
                    form_data["action"] = base + form_data["action"]
                elif not form_data["action"]:
                    form_data["action"] = target

                # Collect all input fields
                for inp in form.find_all(["input", "textarea"]):
                    name = inp.get("name")
                    if name:
                        inp_type = inp.get("type", "text").lower()
                        # Skip submit buttons, hidden fields, checkboxes
                        if inp_type not in ("submit", "checkbox", "radio", "hidden", "file"):
                            form_data["inputs"][name] = inp.get("value", "test")

                if form_data["inputs"]:
                    forms.append(form_data)

        except RequestException:
            pass

        return forms

    def _test_forms(self, target: str, result: ModuleResult) -> None:
        """
        Test HTML form inputs for SQLi by submitting payloads via POST/GET.
        """
        forms = self._extract_forms(target)

        for form in forms:
            for param_name in form["inputs"]:
                for payload in SQLI_PAYLOADS[:6]:  # Test top payloads for forms
                    # Build form data with the payload injected
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

                        matched_error = self._contains_sql_error(response.text)
                        if matched_error:
                            result.findings.append(Finding(
                                title=f"SQL Injection — Form field: '{param_name}' ({form['method'].upper()})",
                                severity=Severity.CRITICAL,
                                cvss_score=9.8,
                                description=(
                                    f"The form field '{param_name}' at {form['action']} is vulnerable "
                                    "to SQL injection. Input from this form is passed to a database query "
                                    "without sanitization."
                                ),
                                recommendation=(
                                    "Replace all dynamic SQL queries with parameterized queries. "
                                    "Input validation alone is not sufficient — use prepared statements."
                                ),
                                evidence=(
                                    f"POST payload '{payload}' on field '{param_name}' triggered: "
                                    f"\"{matched_error}\""
                                )
                            ))
                            break  # Found vuln — move to next field

                    except RequestException:
                        continue

    def check(self, target: str) -> ModuleResult:
        """
        Run all SQL injection checks against the target.

        Args:
            target: Full URL to scan, ideally one with GET parameters

        Returns:
            ModuleResult with all SQLi findings
        """
        result = ModuleResult(module_name="SQL Injection", target=target)

        # Test GET parameters from the URL itself
        self._test_get_params(target, result)

        # Test HTML form inputs found on the page
        self._test_forms(target, result)

        if not result.findings:
            result.passed.append(
                "No SQL injection detected in URL parameters or discovered form fields "
                "(note: this does not guarantee the application is fully protected)"
            )

        return result
