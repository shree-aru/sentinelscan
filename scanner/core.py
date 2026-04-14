"""
SentinelScan - Core Scan Orchestrator (v2)
============================================
Updated to include all Day 2 modules:
  - SQL Injection scanner
  - Reflected XSS scanner
  - CORS Misconfiguration checker
  - Threat Intelligence (Shodan + NVD)

Also supports selective module execution for the FastAPI
quick-scan endpoint (/scan/quick runs only fast modules).
"""

import json
from datetime import datetime
from urllib.parse import urlparse

from scanner.models import ScanReport
from scanner.header_checker import HeaderChecker
from scanner.ssl_checker import SSLChecker
from scanner.dir_scanner import DirectoryScanner
from scanner.sqli_scanner import SQLiScanner
from scanner.xss_scanner import XSSScanner
from scanner.cors_checker import CORSChecker
from scanner.threat_intel import ThreatIntelModule


def normalize_target(target: str) -> str:
    """Normalize a URL — add https:// if missing, lowercase scheme and host."""
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower()
    )
    return normalized.geturl()


def validate_target(target: str) -> tuple[bool, str]:
    """Validate that the target is a usable URL."""
    try:
        parsed = urlparse(target)
        if not parsed.scheme or not parsed.netloc:
            return False, "Invalid URL — missing scheme or hostname"
        if parsed.scheme not in ("http", "https"):
            return False, f"Unsupported scheme '{parsed.scheme}'"
        if "." not in parsed.netloc and parsed.netloc not in ("localhost", "127.0.0.1"):
            return False, f"'{parsed.netloc}' does not look like a valid hostname"
        return True, ""
    except Exception as e:
        return False, str(e)


# Module registry — maps short names (used by FastAPI) to module classes
MODULE_REGISTRY = {
    "headers": HeaderChecker,
    "ssl":     SSLChecker,
    "dirs":    DirectoryScanner,
    "sqli":    SQLiScanner,
    "xss":     XSSScanner,
    "cors":    CORSChecker,
}


class SentinelCore:
    """
    Orchestrates all scanner modules and produces a unified ScanReport.

    Supports selective module execution:
      SentinelCore(modules=["headers", "ssl"])  — run only these two
      SentinelCore()                             — run all modules

    Args:
        timeout:              Request timeout per module (seconds)
        modules:              List of module names to run (None = all)
        include_threat_intel: Whether to run the Shodan/NVD lookup
    """

    def __init__(
        self,
        timeout: int = 10,
        modules: list[str] | None = None,
        include_threat_intel: bool = True
    ):
        self.timeout = timeout
        self.include_threat_intel = include_threat_intel

        # Build the active module list from registry
        if modules:
            # Only run modules that are both requested AND exist in our registry
            active_keys = [m for m in modules if m in MODULE_REGISTRY]
        else:
            # Default: run everything
            active_keys = list(MODULE_REGISTRY.keys())

        # Instantiate each module class with the configured timeout
        self.modules = [MODULE_REGISTRY[key](timeout=timeout) for key in active_keys]

    def scan(self, target: str) -> ScanReport:
        """
        Execute all active modules against the target and return a ScanReport.

        Args:
            target: Normalized URL to scan

        Returns:
            ScanReport with aggregated results from all modules
        """
        target = normalize_target(target)
        is_valid, error_msg = validate_target(target)

        report = ScanReport(
            target=target,
            scan_time=datetime.utcnow().isoformat() + "Z",
            modules_run=[]
        )

        if not is_valid:
            return report

        # Run core scanner modules
        for module in self.modules:
            module_result = module.check(target)
            report.results.append(module_result)
            report.modules_run.append(module_result.module_name)

        # Threat intelligence runs last — it needs the target resolved
        if self.include_threat_intel:
            intel = ThreatIntelModule(max_cve_lookups=5)
            intel_result = intel.check(target)
            report.results.append(intel_result)
            report.modules_run.append(intel_result.module_name)

        return report

    def save_json_report(self, report: ScanReport, output_path: str) -> str:
        """Serialize the ScanReport to a JSON file."""
        def serialize(obj):
            if hasattr(obj, "value"):
                return obj.value
            if hasattr(obj, "__dict__"):
                return obj.__dict__
            return str(obj)

        report_dict = {
            "sentinelscan_version": "2.0",
            "target": report.target,
            "scan_time": report.scan_time,
            "summary": {
                "overall_risk": report.risk_rating(),
                "total_findings": report.total_findings(),
                "critical": report.critical_count(),
                "high": report.high_count(),
                "medium": report.medium_count(),
                "low": report.low_count(),
                "modules_run": report.modules_run,
            },
            "modules": [
                {
                    "module": r.module_name,
                    "error": r.error,
                    "findings": [
                        {
                            "title": f.title,
                            "severity": f.severity.value,
                            "cvss_score": f.cvss_score,
                            "description": f.description,
                            "recommendation": f.recommendation,
                            "evidence": f.evidence,
                        }
                        for f in r.findings
                    ],
                    "passed_checks": r.passed
                }
                for r in report.results
            ]
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, default=serialize)

        return output_path
