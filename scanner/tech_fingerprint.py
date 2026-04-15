"""
SentinelScan - Technology Stack Fingerprinter
==============================================
Module 8: Passively identifies the technology stack running on
the target — CMS, web framework, server, CDN, analytics tools.

Real-world importance:
  - Knowing what software a target runs narrows which CVEs apply
  - Attackers fingerprint technology BEFORE choosing exploits
  - Security teams use fingerprinting to build accurate asset inventories
  - Tools like Wappalyzer (used by millions) do exactly this

Detection methods (all passive — no active probing):
  1. HTTP response headers (Server, X-Powered-By, X-Generator, etc.)
  2. HTML source patterns (WordPress paths, framework-specific tags)
  3. Cookie names (PHPSESSID, JSESSIONID, laravel_session, etc.)
  4. Meta tags (generator meta tag, framework-specific attributes)
  5. JavaScript file paths (/wp-includes/, /__next/, /angular.min.js)

Why passive matters:
  Passive fingerprinting makes zero unusual requests beyond a normal
  browser GET. It's completely safe and legal even on systems you
  don't own (though you should still have permission to scan them).

Learning goals:
  - String matching against real-world patterns
  - Working with HTTP cookies (response.cookies)
  - Regex in Python for more flexible pattern matching
  - Building a classification system with categories
"""

import re
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

from scanner.models import Finding, ModuleResult, Severity


# ─────────────────────────────────────────────────────────────────────────────
#  TECHNOLOGY SIGNATURES DATABASE
#
#  Each entry: (pattern_to_match, technology_name, category, confidence)
#
#  Sources are checked in order: headers → cookies → html → meta → scripts
#  Confidence: "confirmed" (very specific match) vs "likely" (generic match)
# ─────────────────────────────────────────────────────────────────────────────

HEADER_SIGNATURES = {
    # ── Web Servers ───────────────────────────────────────────────────────────
    "server": [
        ("apache",             "Apache HTTP Server",    "Web Server"),
        ("nginx",              "Nginx",                 "Web Server"),
        ("microsoft-iis",      "Microsoft IIS",         "Web Server"),
        ("litespeed",          "LiteSpeed",             "Web Server"),
        ("openresty",          "OpenResty (Nginx+Lua)", "Web Server"),
        ("caddy",              "Caddy",                 "Web Server"),
        ("cloudflare",         "Cloudflare",            "CDN / Proxy"),
        ("awselb",             "AWS Elastic Load Balancer", "Infrastructure"),
        ("AmazonS3",           "Amazon S3",             "Cloud Storage"),
    ],
    # ── Backend Frameworks / Languages ───────────────────────────────────────
    "x-powered-by": [
        ("php",                "PHP",                   "Backend Language"),
        ("asp.net",            "ASP.NET",               "Backend Framework"),
        ("express",            "Express.js",            "Backend Framework"),
        ("next.js",            "Next.js",               "Backend Framework"),
        ("django",             "Django",                "Backend Framework"),
        ("rails",              "Ruby on Rails",         "Backend Framework"),
        ("laravel",            "Laravel",               "Backend Framework"),
        ("spring",             "Spring Boot",           "Backend Framework"),
    ],
    # ── CMS-Specific ──────────────────────────────────────────────────────────
    "x-generator": [
        ("wordpress",          "WordPress",             "CMS"),
        ("drupal",             "Drupal",                "CMS"),
        ("joomla",             "Joomla",                "CMS"),
    ],
    # ── CDN / Security Services ──────────────────────────────────────────────
    "cf-ray": [
        ("",                   "Cloudflare",            "CDN / Security"),  # Header presence = Cloudflare
    ],
    "x-cache": [
        ("cloudfront",         "AWS CloudFront",        "CDN"),
        ("fastly",             "Fastly CDN",            "CDN"),
        ("varnish",            "Varnish Cache",         "Cache"),
    ],
    "x-drupal-cache": [
        ("",                   "Drupal",                "CMS"),
    ],
    "x-pingback": [
        ("xmlrpc.php",         "WordPress",             "CMS"),
    ],
    "x-shopify-stage": [
        ("",                   "Shopify",               "E-commerce Platform"),
    ],
}

COOKIE_SIGNATURES = [
    ("PHPSESSID",              "PHP",                   "Backend Language"),
    ("JSESSIONID",             "Java / Apache Tomcat",  "Backend Language"),
    ("ASP.NET_SessionId",      "ASP.NET",               "Backend Framework"),
    ("laravel_session",        "Laravel (PHP)",         "Backend Framework"),
    ("django",                 "Django",                "Backend Framework"),
    ("csrftoken",              "Django",                "Backend Framework"),
    ("_rails_session",         "Ruby on Rails",         "Backend Framework"),
    ("wp-settings",            "WordPress",             "CMS"),
    ("shopify_session",        "Shopify",               "E-commerce Platform"),
    ("Magento",                "Magento",               "E-commerce Platform"),
]

HTML_SIGNATURES = [
    # WordPress
    (r"/wp-content/",          "WordPress",             "CMS"),
    (r"/wp-includes/",         "WordPress",             "CMS"),
    (r"wp-json",               "WordPress REST API",    "CMS"),
    # Joomla
    (r"/components/com_",      "Joomla",                "CMS"),
    (r"joomla",                "Joomla",                "CMS"),
    # Drupal
    (r"Drupal\.settings",      "Drupal",                "CMS"),
    (r"/sites/default/files",  "Drupal",                "CMS"),
    # Magento
    (r"Mage\.Cookies",         "Magento",               "E-commerce"),
    (r"var BLANK_URL",         "Magento",               "E-commerce"),
    # Next.js
    (r"__NEXT_DATA__",         "Next.js",               "Frontend Framework"),
    (r"/_next/static",         "Next.js",               "Frontend Framework"),
    # Nuxt.js
    (r"__NUXT__",              "Nuxt.js",               "Frontend Framework"),
    # React
    (r"react\.development",    "React",                 "Frontend Library"),
    (r"react-root",            "React",                 "Frontend Library"),
    # Angular
    (r"ng-version=",           "Angular",               "Frontend Framework"),
    (r"/angular",              "Angular",               "Frontend Framework"),
    # Vue
    (r"__vue_app__",           "Vue.js",                "Frontend Framework"),
    # Gatsby
    (r"___gatsby",             "Gatsby",                "Static Site Generator"),
    # Bootstrap
    (r"bootstrap.min.css",     "Bootstrap",             "CSS Framework"),
    (r"bootstrap.min.js",      "Bootstrap",             "CSS Framework"),
    # jQuery
    (r"jquery.min.js",         "jQuery",                "JS Library"),
    (r"jquery-",               "jQuery",                "JS Library"),
    # Google Analytics / Tag Manager
    (r"google-analytics.com",  "Google Analytics",      "Analytics"),
    (r"googletagmanager.com",  "Google Tag Manager",    "Analytics"),
    # Cloudflare JS
    (r"cloudflare",            "Cloudflare",            "CDN / Security"),
]

META_TAG_SIGNATURES = [
    ("generator", "wordpress", "WordPress",  "CMS"),
    ("generator", "joomla",    "Joomla",     "CMS"),
    ("generator", "drupal",    "Drupal",     "CMS"),
    ("generator", "hugo",      "Hugo",       "Static Site Generator"),
    ("generator", "gatsby",    "Gatsby",     "Static Site Generator"),
    ("generator", "jekyll",    "Jekyll",     "Static Site Generator"),
    ("generator", "wix",       "Wix",        "Website Builder"),
    ("generator", "squarespace","Squarespace","Website Builder"),
    ("generator", "webflow",   "Webflow",    "Website Builder"),
]


class TechFingerprinter:
    """
    Passively identifies the technology stack of a target website.

    Collects all detections, deduplicates them, and returns a structured
    report of what technologies were identified and from which signals.

    Usage:
        fp = TechFingerprinter()
        result = fp.check("https://example.com")
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    def _normalize(self, text: str) -> str:
        return (text or "").lower().strip()

    def check(self, target: str) -> ModuleResult:
        """
        Run passive technology fingerprinting against the target.

        Returns:
            ModuleResult with detected technologies as passed checks,
            and security-relevant technologies as findings
        """
        result = ModuleResult(module_name="Technology Fingerprint", target=target)
        detected = {}  # tech_name -> {category, sources}

        def add_detection(name: str, category: str, source: str):
            if name not in detected:
                detected[name] = {"category": category, "sources": []}
            if source not in detected[name]["sources"]:
                detected[name]["sources"].append(source)

        try:
            response = self.session.get(
                target,
                timeout=self.timeout,
                allow_redirects=True
            )
        except RequestException as e:
            result.error = f"Could not connect to {target}: {str(e)[:100]}"
            return result

        headers = {k.lower(): v for k, v in response.headers.items()}
        html = response.text
        cookies = {c.lower(): c for c in response.cookies.keys()}

        # ── 1. Header-based detection ────────────────────────────────────────
        for header_name, signatures in HEADER_SIGNATURES.items():
            if header_name not in headers:
                continue
            header_value = self._normalize(headers[header_name])

            for pattern, tech_name, category in signatures:
                if pattern == "" or pattern.lower() in header_value:
                    add_detection(tech_name, category, f"Header: {header_name}")

        # ── 2. Cookie-based detection ────────────────────────────────────────
        for cookie_name, tech_name, category in COOKIE_SIGNATURES:
            for resp_cookie in response.cookies.keys():
                if cookie_name.lower() in resp_cookie.lower():
                    add_detection(tech_name, category, f"Cookie: {resp_cookie}")

        # ── 3. HTML source pattern matching ──────────────────────────────────
        html_lower = html.lower()
        for pattern, tech_name, category in HTML_SIGNATURES:
            if re.search(pattern, html, re.IGNORECASE):
                add_detection(tech_name, category, "HTML source")

        # ── 4. Meta tag generator field ──────────────────────────────────────
        try:
            soup = BeautifulSoup(html, "html.parser")
            for meta in soup.find_all("meta"):
                meta_name = self._normalize(meta.get("name", ""))
                meta_content = self._normalize(meta.get("content", ""))
                for attr, keyword, tech_name, category in META_TAG_SIGNATURES:
                    if meta_name == attr and keyword in meta_content:
                        add_detection(tech_name, category, "Meta generator tag")
        except Exception:
            pass

        # ── 5. Build findings and passed checks ──────────────────────────────
        if not detected:
            result.passed.append(
                "No technology signatures detected "
                "(site may use custom stack or have fingerprinting suppressed)"
            )
            return result

        # Group detections by category for clean output
        by_category: dict[str, list] = {}
        for tech, info in detected.items():
            cat = info["category"]
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append((tech, info["sources"]))

        # Informational summary
        all_techs = list(detected.keys())
        result.passed.append(
            f"Detected {len(all_techs)} technolog{'y' if len(all_techs)==1 else 'ies'}: "
            + " | ".join(all_techs[:8])
            + ("..." if len(all_techs) > 8 else "")
        )

        # Per-category details
        for category, techs in sorted(by_category.items()):
            tech_list = ", ".join(t[0] for t in techs)
            result.passed.append(f"  {category}: {tech_list}")

        # ── 6. Security-relevant findings ────────────────────────────────────
        # WordPress: known to be heavily targeted, version disclosure is common
        if "WordPress" in detected:
            wp_version_match = re.search(r"ver=(\d+\.\d+[\.\d]*)", html)
            version_str = f" (ver={wp_version_match.group(1)})" if wp_version_match else ""
            result.findings.append(Finding(
                title=f"WordPress CMS Detected{version_str}",
                severity=Severity.INFO,
                cvss_score=0.0,
                description=(
                    "The target is running WordPress. WordPress is the world's most popular CMS "
                    "which also makes it the most actively targeted. "
                    "Outdated themes, plugins, and core are a leading cause of website compromises."
                ),
                recommendation=(
                    "1. Keep WordPress core, themes, and plugins updated\n"
                    "2. Remove unused plugins and themes\n"
                    "3. Use a security plugin (Wordfence, Sucuri) for active monitoring\n"
                    "4. Hide version numbers: add 'remove_action(\"wp_head\", \"wp_generator\")'"
                ),
                evidence=f"Detection sources: {', '.join(detected['WordPress']['sources'])}"
            ))

        # PHP version disclosure (e.g. X-Powered-By: PHP/7.4.3)
        xpb = headers.get("x-powered-by", "")
        php_version = re.search(r"PHP/([\d.]+)", xpb, re.IGNORECASE)
        if php_version:
            result.findings.append(Finding(
                title=f"PHP Version Disclosed: {php_version.group(0)}",
                severity=Severity.LOW,
                cvss_score=2.0,
                description=(
                    f"The X-Powered-By header exposes the exact PHP version ({php_version.group(0)}). "
                    "Attackers can cross-reference this version against known CVEs for that PHP release."
                ),
                recommendation=(
                    "Set 'expose_php = Off' in your php.ini file to suppress version disclosure."
                ),
                evidence=f"X-Powered-By: {xpb}"
            ))

        # Java / Apache Tomcat via JSESSIONID (common enterprise attack target)
        if "Java / Apache Tomcat" in detected:
            result.findings.append(Finding(
                title="Java/Tomcat Application Detected",
                severity=Severity.INFO,
                cvss_score=0.0,
                description=(
                    "A Java-based application (likely Apache Tomcat) is detected. "
                    "Tomcat management panels (/manager/html) are frequently targeted when left "
                    "exposed with default credentials."
                ),
                recommendation=(
                    "Verify /manager/html is not publicly accessible. "
                    "Change default Tomcat admin credentials. "
                    "Consider running a Tomcat version check against NVD for known CVEs."
                ),
                evidence=f"JSESSIONID cookie detected"
            ))

        return result
