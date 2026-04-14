"""
SentinelScan - Sensitive Directory & File Scanner
==================================================
Module 3: Probes for exposed sensitive files and directories
that should NEVER be publicly accessible.

Real-world importance:
  - Exposed .git = source code + API keys stolen in seconds
  - Exposed .env = database passwords, cloud credentials leaked
  - This type of misconfiguration causes massive data breaches
  - Capital One, Uber, and many others were breached via exposed files

IMPORTANT — Ethical use:
  This module only checks for files that are ACCIDENTALLY exposed.
  It does NOT exploit them — it just checks if they respond with 200 OK.
  Only scan systems you own or have written permission to test.

Learning goals:
  - concurrent.futures for multi-threading (scan faster!)
  - How HTTP status codes work
  - List comprehensions and generator patterns
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from requests.exceptions import RequestException

from scanner.models import Finding, ModuleResult, Severity


# ─────────────────────────────────────────────────────────────────────────────
#  SENSITIVE PATHS DATABASE
#  Each entry: (path, risk_description, severity, cvss_score)
#  Organized by category for readability.
# ─────────────────────────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    # ── Source Control (CRITICAL — leaks your entire codebase) ───────────
    ("/.git/config",         "Exposed Git repository config — reveals remote URLs and possibly credentials",  Severity.CRITICAL, 9.8),
    ("/.git/HEAD",           "Exposed Git HEAD file — attacker can reconstruct full source code",               Severity.CRITICAL, 9.8),
    ("/.svn/entries",        "Exposed SVN repository — full source code accessible",                           Severity.CRITICAL, 9.8),

    # ── Configuration & Secrets (CRITICAL — passwords, API keys) ─────────
    ("/.env",                "Exposed .env file — contains DB passwords, API keys, secrets",                   Severity.CRITICAL, 9.8),
    ("/.env.local",          "Exposed .env.local — local environment secrets",                                 Severity.CRITICAL, 9.8),
    ("/.env.production",     "Exposed production environment file with live credentials",                      Severity.CRITICAL, 9.8),
    ("/config.php",          "Exposed PHP config file — may contain DB credentials",                           Severity.CRITICAL, 9.5),
    ("/wp-config.php",       "Exposed WordPress config — contains MySQL database password",                    Severity.CRITICAL, 9.5),
    ("/configuration.php",   "Exposed Joomla configuration file — contains DB credentials",                    Severity.CRITICAL, 9.5),
    ("/config/database.yml", "Exposed Rails database config — DB host, name, password",                       Severity.CRITICAL, 9.5),
    ("/secrets.json",        "Exposed secrets file — likely contains API keys or passwords",                   Severity.CRITICAL, 9.5),
    ("/credentials.json",    "Exposed credentials file — high risk of authentication bypass",                  Severity.CRITICAL, 9.5),
    ("/key.pem",             "Exposed private key file — can decrypt all encrypted traffic",                   Severity.CRITICAL, 10.0),
    ("/id_rsa",              "Exposed SSH private key — grants server access to anyone",                       Severity.CRITICAL, 10.0),

    # ── Backup Files (HIGH — may contain sensitive data) ─────────────────
    ("/backup.zip",          "Backup archive exposed — may contain full site source and data",                 Severity.HIGH, 8.5),
    ("/backup.tar.gz",       "Compressed backup exposed — full codebase or database may be inside",            Severity.HIGH, 8.5),
    ("/backup.sql",          "SQL dump exposed — full database contents accessible",                           Severity.HIGH, 8.8),
    ("/dump.sql",            "SQL dump exposed — full database may be downloadable",                           Severity.HIGH, 8.8),
    ("/db.sql",              "Database SQL file exposed",                                                       Severity.HIGH, 8.8),
    ("/database.sql",        "Database backup exposed — all user data may be accessible",                      Severity.HIGH, 8.8),

    # ── Admin Panels (HIGH — unprotected admin = full control) ───────────
    ("/admin",               "Admin panel accessible — verify it requires strong authentication",              Severity.HIGH, 7.5),
    ("/admin/",              "Admin directory accessible",                                                      Severity.HIGH, 7.5),
    ("/wp-admin/",           "WordPress admin panel accessible",                                               Severity.HIGH, 7.0),
    ("/administrator/",      "Joomla administrator panel accessible",                                          Severity.HIGH, 7.0),
    ("/phpmyadmin/",         "phpMyAdmin exposed — direct database access panel",                              Severity.CRITICAL, 9.8),
    ("/adminer.php",         "Adminer database manager exposed",                                               Severity.CRITICAL, 9.5),
    ("/cpanel",              "cPanel hosting control panel exposed",                                           Severity.HIGH, 8.0),

    # ── Log Files (MEDIUM — may contain usernames, emails, errors) ────────
    ("/server.log",          "Server log file exposed — may contain usernames, IPs, error details",           Severity.MEDIUM, 5.3),
    ("/error.log",           "Error log exposed — reveals internal paths and stack traces",                    Severity.MEDIUM, 5.3),
    ("/access.log",          "Access log exposed — reveals all visitor activity",                              Severity.MEDIUM, 4.8),
    ("/debug.log",           "Debug log exposed — may contain sensitive application data",                     Severity.MEDIUM, 5.0),
    ("/application.log",     "Application log file exposed",                                                   Severity.MEDIUM, 5.0),

    # ── Development Files (MEDIUM — shouldn't be on production) ──────────
    ("/phpinfo.php",         "PHP info page exposed — reveals full server configuration to attackers",         Severity.HIGH, 7.5),
    ("/info.php",            "PHP info page exposed — server environment details leak",                        Severity.HIGH, 7.5),
    ("/test.php",            "Test PHP file accessible — should not exist on production",                      Severity.MEDIUM, 4.5),
    ("/readme.html",         "Readme file exposed — may reveal CMS version (aids targeted attacks)",           Severity.LOW, 3.1),
    ("/README.md",           "README accessible — may reveal technology stack and version",                    Severity.LOW, 2.5),
    ("/CHANGELOG.md",        "Changelog exposed — reveals versions and may hint at known vulnerabilities",     Severity.LOW, 2.5),
    ("/package.json",        "package.json exposed — reveals exact dependency versions",                       Severity.MEDIUM, 4.0),
    ("/composer.json",       "composer.json exposed — PHP dependencies and versions revealed",                 Severity.MEDIUM, 4.0),
    ("/requirements.txt",    "requirements.txt exposed — Python dependencies revealed",                        Severity.LOW, 2.5),

    # ── Cloud & Infrastructure (CRITICAL) ────────────────────────────────
    ("/.aws/credentials",    "AWS credentials file exposed — full cloud account access risk",                  Severity.CRITICAL, 10.0),
    ("/.ssh/authorized_keys","SSH authorized keys exposed — server access control file",                       Severity.CRITICAL, 9.5),
    ("/docker-compose.yml",  "Docker Compose config exposed — may reveal service ports and credentials",       Severity.HIGH, 7.0),
    ("/Dockerfile",          "Dockerfile exposed — reveals server build process and base images",              Severity.LOW, 3.5),
    ("/.htpasswd",           "HTPASSWD file exposed — contains hashed user credentials",                      Severity.HIGH, 8.0),
    ("/.htaccess",           "HTACCESS file exposed — reveals server rewrite rules and access controls",       Severity.MEDIUM, 4.5),
]

# Status codes that indicate a path exists and is accessible
ACCESSIBLE_CODES = {200, 206}
# Status codes that suggest a path might exist but requires auth
POSSIBLE_CODES = {401, 403}


class DirectoryScanner:
    """
    Scans for publicly accessible sensitive files and directories.

    Uses multi-threading to check multiple paths in parallel,
    making the scan fast even with a large path list.

    Usage:
        scanner = DirectoryScanner(max_workers=20)
        result = scanner.check("https://example.com")
    """

    def __init__(self, timeout: int = 8, max_workers: int = 15):
        """
        Args:
            timeout:     Request timeout per path (seconds)
            max_workers: Number of parallel threads (don't go too high — be respectful)
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SentinelScan/1.0 Security Scanner (Authorized Use Only)"
        })

    def _probe_path(self, base_url: str, path: str, description: str,
                    severity: Severity, cvss: float) -> Finding | None:
        """
        Send a single HTTP request to check if a sensitive path is accessible.

        Returns:
            Finding if the path is exposed, None if it's safe/unreachable
        """
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,  # Don't follow redirects — 301 to login page means NOT exposed
                stream=True             # Don't download full body — we just need the status code
            )
            response.close()

            if response.status_code in ACCESSIBLE_CODES:
                return Finding(
                    title=f"Exposed Sensitive File: {path}",
                    severity=severity,
                    cvss_score=cvss,
                    description=description,
                    recommendation=(
                        f"Immediately restrict access to '{path}':\n"
                        "  1. Remove the file from the public web root\n"
                        "  2. Add it to .gitignore to prevent future exposure\n"
                        "  3. Add server-level access controls if the file is needed"
                    ),
                    evidence=f"HTTP {response.status_code} at {url}"
                )

            elif response.status_code in POSSIBLE_CODES:
                return Finding(
                    title=f"Restricted but Detectable: {path}",
                    severity=Severity.LOW,
                    cvss_score=2.0,
                    description=(
                        f"Path '{path}' exists but requires authentication (HTTP {response.status_code}). "
                        "Its existence confirms the technology stack to attackers."
                    ),
                    recommendation=(
                        "Move sensitive files outside the web root entirely. "
                        "Their existence at predictable paths aids targeted attacks."
                    ),
                    evidence=f"HTTP {response.status_code} at {url}"
                )

        except (RequestException, OSError):
            pass  # Path not accessible — this is the safe outcome

        return None

    def check(self, target: str) -> ModuleResult:
        """
        Scan for all sensitive paths in parallel using thread pool.

        Args:
            target: Base URL to scan (e.g., "https://example.com")

        Returns:
            ModuleResult with all discovered exposed files
        """
        result = ModuleResult(module_name="Sensitive Files & Directories", target=target)

        # Submit all path checks to thread pool simultaneously
        # ThreadPoolExecutor: Python's built-in way to run tasks in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Create a future for each path check
            future_to_path = {
                executor.submit(
                    self._probe_path, target, path, description, severity, cvss
                ): path
                for path, description, severity, cvss in SENSITIVE_PATHS
            }

            # Collect results as they complete (not in submission order)
            for future in as_completed(future_to_path):
                finding = future.result()
                if finding:
                    result.findings.append(finding)

        # Sort findings by severity (CRITICAL first) for better readability
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        result.findings.sort(key=lambda f: severity_order[f.severity])

        # Summary in passed list
        paths_checked = len(SENSITIVE_PATHS)
        paths_clean = paths_checked - len(result.findings)
        result.passed.append(
            f"Checked {paths_checked} sensitive paths — {paths_clean} not accessible"
        )

        return result
