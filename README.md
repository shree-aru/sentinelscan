# SentinelScan

A command-line web security scanner that checks for common misconfigurations before someone else finds them for you.

I built this because most free security scanners are either bloated, outdated, or require a full Kali Linux setup just to run. SentinelScan is a single Python project you can clone and run in under two minutes.

It is not a replacement for Burp Suite or a full penetration test. It is a fast first-pass scanner — the kind of thing you run against your own server to catch the obvious mistakes.

---

## What it checks

**Security headers** — checks for missing or misconfigured HTTP response headers that protect against XSS, clickjacking, protocol downgrade attacks, and information leakage. Each missing header comes with an explanation of why it matters and the exact line to add to your server config.

**SSL/TLS certificate** — checks certificate validity and expiry, flags deprecated TLS versions (1.0 and 1.1), and detects self-signed certificates. Uses Python's built-in ssl module, no external tools required.

**Sensitive files and directories** — probes 47 common paths that should never be publicly accessible: `.git`, `.env`, backup archives, SQL dumps, admin panels, phpMyAdmin, AWS credentials, private keys, and so on. Uses multi-threading so the check runs fast even with a large path list.

All findings are scored using CVSS (Common Vulnerability Scoring System), which is the same standard used by Microsoft, Google, and most major security teams for rating vulnerability severity.

---

## Setup

You need Python 3.10 or higher.

```
git clone https://github.com/yourusername/sentinelscan.git
cd sentinelscan
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux / Mac
pip install -r requirements.txt
```

---

## Usage

Basic scan:

```
python main.py https://example.com
```

Save the report to a specific file:

```
python main.py https://example.com --output reports/example.json
```

Adjust the timeout (default is 10 seconds):

```
python main.py https://example.com --timeout 15
```

Only show findings, skip the passed checks:

```
python main.py https://example.com --quiet
```

Skip the banner:

```
python main.py https://example.com --no-banner
```

The tool will ask you to confirm that you own the target or have written permission before it starts. Scanning systems without permission is illegal. Only use this on your own infrastructure.

---

## Output

The terminal output shows each module's findings with severity levels (CRITICAL, HIGH, MEDIUM, LOW), CVSS scores, a description of the risk, the evidence observed, and a fix recommendation.

At the end, it prints a summary table with the overall risk rating and breakdown by severity.

A JSON report is also saved automatically. The JSON format is machine-readable so the output can feed into dashboards, CI/CD pipelines, or other tools.

Example JSON structure:

```json
{
  "sentinelscan_version": "1.0",
  "target": "https://example.com",
  "scan_time": "2026-04-14T14:49:56Z",
  "summary": {
    "overall_risk": "HIGH",
    "total_findings": 5,
    "critical": 0,
    "high": 2,
    "medium": 2,
    "low": 1
  },
  "modules": [...]
}
```

---

## Project structure

```
sentinelscan/
    main.py                  entry point, CLI and terminal output
    requirements.txt
    scanner/
        models.py            data classes: Finding, ModuleResult, ScanReport, Severity
        header_checker.py    HTTP security headers analysis
        ssl_checker.py       SSL/TLS certificate analysis
        dir_scanner.py       sensitive file and directory probing
        core.py              orchestrates modules, handles JSON export
```

---

## Why specific design decisions

**Dictionary-driven config** — adding a new header check or sensitive path requires one line of config, not a new if/else block. Makes it easy to extend.

**Multi-threading for directory scan** — the directory module uses `concurrent.futures.ThreadPoolExecutor` to probe all paths in parallel. A sequential scan of 47 paths over a slow connection could take minutes. The threaded version finishes in seconds.

**Exit codes** — the scanner exits with code 1 if any CRITICAL or HIGH findings are present, and 0 otherwise. This makes it usable in CI/CD pipelines as a build gate. If security regressions are introduced, the build fails.

**No external binaries** — everything runs in pure Python. No nmap, no curl wrappers, no system dependencies beyond pip packages.

---

## Limitations

This is a passive/non-destructive scanner. It checks HTTP responses and probes known paths — it does not fuzz inputs, attempt authentication bypass, or run active exploits.

The directory scanner only checks a fixed list of 47 paths. It is not a full dirbusting tool. For thorough enumeration you would use something like `ffuf` or `gobuster` with a larger wordlist, but that is a different use case.

SSL checks are done by attempting a real TLS handshake using Python's ssl module. If the server is behind a load balancer that handles TLS termination, some checks may report differently than expected.

---

## What is coming next

- SQL injection detection (GET and POST parameter testing)
- Reflected XSS scanning
- CORS misconfiguration checks
- REST API wrapper using FastAPI so you can run scans programmatically
- HTML and PDF report generation

---

## Legal

Only use this tool against systems you own or have explicit written permission to test. Unauthorized scanning is illegal in most countries, including under India's IT Act (Section 66), the US Computer Fraud and Abuse Act, and the UK Computer Misuse Act.

This tool was written for learning, research, and authorized security audits.
