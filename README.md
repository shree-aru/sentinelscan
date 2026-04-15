# SentinelScan

A multi-module web security scanner built for real-world use. It combines active vulnerability detection with passive threat intelligence to give a complete picture of a target's security posture. Results come out as a colored terminal report, a structured JSON file, a professional PDF, and a live web dashboard.

I built this as a portfolio project while learning security engineering. The goal was to build something that actually works against real targets, not a toy that just checks one header.

---

## What it does

**Active scanning — things it probes for directly:**

- Security headers: checks for CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. Missing headers are scored with CVSS and come with exact server config lines to add.
- SSL/TLS: certificate validity and expiry, deprecated protocol versions (TLS 1.0/1.1), self-signed certificates, cipher suite issues.
- Sensitive files: multi-threaded probe of 47 paths that should never be public — `.git`, `.env`, `/phpMyAdmin`, SQL dumps, backup archives, AWS credential files, private keys.
- SQL injection: tests GET parameters and discovered HTML form fields with a payload set designed to trigger SQL error leakage. Detects error-based SQLi across MySQL, PostgreSQL, Oracle, MSSQL, and SQLite.
- Reflected XSS: injects payloads into URL parameters and form inputs, assesses reflection context (raw HTML vs. attribute vs. event handler) to determine severity accurately.
- CORS misconfiguration: tests for wildcard origins, origin reflection, null origin acceptance, and pre-flight configuration issues.

**Passive intelligence — no extra probing required:**

- Technology fingerprinting: detects 50+ technologies from response headers, cookies, HTML source, and meta tags. Identifies CMS (WordPress, Drupal, Joomla), frameworks (Next.js, Laravel, Django, Rails), CDNs (Cloudflare, Fastly), and languages (PHP, Java, ASP.NET).
- Threat intelligence: resolves the target hostname to an IP, queries Shodan InternetDB (free, no API key required) for open ports and known CVEs, then fetches full CVE descriptions and CVSS scores from the NVD API. Real threat data — the kind that Qualys and Tenable sell subscriptions for.

All findings use CVSS scores. The overall risk rating (CRITICAL / HIGH / MEDIUM / LOW / SECURE) is based on the severity of the worst finding.

---

## Architecture

```
sentinelscan/
    main.py                      CLI entry point
    requirements.txt
    render.yaml                  Render.com deployment config
    scanner/
        models.py                Finding, ModuleResult, ScanReport — data layer
        header_checker.py        HTTP security headers
        ssl_checker.py           SSL/TLS certificate analysis
        dir_scanner.py           Sensitive path discovery (multi-threaded)
        sqli_scanner.py          SQL injection detection
        xss_scanner.py           Reflected XSS detection
        cors_checker.py          CORS misconfiguration checks
        tech_fingerprint.py      Technology stack identification
        threat_intel.py          Shodan + NVD integration
        core.py                  Orchestrator — runs modules, generates reports
    reporter/
        pdf_reporter.py          PDF report generator (fpdf2)
    api/
        main.py                  FastAPI REST API v2
        auth.py                  API key authentication (dependency injection)
    dashboard/
        index.html               Live browser dashboard
```

The core design pattern is composition: each scanner is a standalone class with a `check(target) -> ModuleResult` method. Adding a new scanner means writing one file and adding it to the registry in `core.py`. Nothing else changes.

---

## Setup

Python 3.10 or higher required.

```
git clone https://github.com/shree-aru/sentinelscan.git
cd sentinelscan
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux / Mac
pip install -r requirements.txt
```

---

## CLI usage

Basic scan (all modules):

```
python main.py https://example.com
```

Full scan with PDF report:

```
python main.py https://example.com --pdf report.pdf
```

Skip threat intelligence for faster scans:

```
python main.py https://example.com --no-intel --timeout 15
```

Quick scan with all output options:

```
python main.py https://example.com --output scan.json --pdf report.pdf --timeout 12
```

Available flags:

```
--output FILE    Save JSON report to this path (auto-named if not set)
--pdf FILE       Also generate a PDF report
--timeout N      Request timeout in seconds (default: 10)
--no-intel       Skip Shodan + NVD lookups (faster, offline-friendly)
--no-banner      Skip the ASCII banner
--quiet          Only print findings, skip passed checks
```

---

## REST API

Start the API server:

```
uvicorn api.main:app --reload --port 8000
```

Interactive documentation is auto-generated at `http://localhost:8000/docs`.

**Authentication** — all scan endpoints require the `X-API-Key` header.
Default dev key: `sentinel-dev-key-2024`
In production: set the `SENTINEL_API_KEY` environment variable.

**Endpoints:**

```
POST /scan/async         Start a background scan, returns scan_id immediately
GET  /scan/{scan_id}     Poll for status and results
GET  /scans              List last 10 scans
POST /scan               Synchronous scan (blocks until complete, good for CI/CD)
POST /scan/quick         Fast scan — headers, SSL, CORS only (3-8 seconds)
GET  /health             Health check, no auth required
GET  /docs               Swagger UI
```

**Rate limits:**
- Full scan endpoints: 5 requests per minute per IP
- Quick scan: 20 requests per minute per IP
- Status polling: 60 requests per minute per IP

Example — start an async scan:

```bash
curl -X POST http://localhost:8000/scan/async \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sentinel-dev-key-2024" \
  -d '{"target": "https://example.com", "include_threat_intel": true}'
```

Response:

```json
{
  "scan_id": "3f2a1b4c-...",
  "status": "queued",
  "target": "https://example.com",
  "message": "Poll GET /scan/3f2a1b4c-... for results."
}
```

---

## Web dashboard

Open `dashboard/index.html` directly in your browser while the API is running. The dashboard calls `localhost:8000` by default (configurable in the UI).

Features: animated radar scan, real-time module progress, animated finding counters, color-coded severity breakdown, collapsible per-module finding panels, evidence and fix recommendations for every issue.

---

## Deploy to Render.com

This repo includes `render.yaml` for one-click deployment.

1. Go to [render.com](https://render.com) and connect your GitHub account
2. Click New → Web Service → select this repo
3. Render detects `render.yaml` automatically
4. Set `SENTINEL_API_KEY` as an environment variable in Render's dashboard
5. Deploy — you get a public URL like `https://sentinelscan-api.onrender.com`

Point `dashboard/index.html` at your Render URL to run scans from anywhere.

---

## Output formats

**Terminal** — color-coded with Rich: severity-badged findings, CVSS scores, passed check indicators, and a summary table at the end.

**JSON** — machine-readable, suitable for piping into dashboards, CI/CD pipelines, or other tools. Saved automatically after every scan.

**PDF** — cover page with risk rating badge, executive summary with findings breakdown table, per-module detailed findings with descriptions and fix recommendations. Generated with `--pdf filename.pdf`.

---

## Design decisions

**Why multi-threading in the directory scanner?**
47 HTTP requests over a 500ms RTT connection would take 23+ seconds sequentially. Threaded, it runs in 3–5 seconds. Python's `ThreadPoolExecutor` is the right tool for I/O-bound parallel work.

**Why Shodan InternetDB instead of the full Shodan API?**
InternetDB is completely free with no API key. It covers the main value: open ports and known CVEs for any public IP. The full Shodan API adds more detail but requires payment and is overkill for a scanner that already detects active vulnerabilities.

**Why in-memory scan storage in the API?**
For a portfolio project and small deployments, a dict is sufficient and has zero dependencies. In production at scale, you would replace it with Redis. The interface (scan_id, polling) stays the same — only the storage backend changes.

**Why FastAPI over Flask?**
Auto-generated Swagger docs, Pydantic validation, native async support, and faster performance. It also has better typing support, which makes the code easier to maintain.

**Why the async scan pattern (start + poll) instead of a long HTTP request?**
Scans take 30–120 seconds. A long synchronous HTTP request will time out behind most proxies and load balancers. The async pattern (get a scan_id immediately, poll for results) is how production APIs like VirusTotal and Shodan work.

---

## Limitations

- SQL injection and XSS detection is error-based and reflection-based only. Blind SQLi (where no error is shown) and stored XSS require separate tooling.
- The directory scanner uses a fixed list of 47 paths. It is not a full wordlist-based fuzzing tool.
- Threat intelligence depends on Shodan having indexed the target IP. Hosts behind Cloudflare or other CDNs will show Cloudflare's IP, not the origin server.
- In-memory scan storage means all scans are lost if the API server restarts.

---

## What is coming next

- Subdomain enumeration
- Open redirect detection
- JWT misconfiguration checks
- CI/CD pipeline GitHub Action for automated scanning on every pull request

---

## Legal

Only use this tool against systems you own or have explicit written permission to test. Unauthorized scanning is illegal in most countries including under India's IT Act (Section 66), the US Computer Fraud and Abuse Act, and the UK Computer Misuse Act.

Built for learning, authorized security research, and professional security assessments.
