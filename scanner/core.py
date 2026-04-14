"""
SentinelScan - Core Scan Orchestrator
=======================================
The brain of SentinelScan. This module:
  1. Validates the target URL
  2. Runs all scanner modules
  3. Aggregates results into a single ScanReport
  4. Saves results to JSON

Think of this like an "assembly line manager":
  - Header checker works on one thing
  - SSL checker works on another
  - Director scanner works on another
  - The orchestrator (this file) coordinates them all

Learning goals:
  - Composition pattern (combine modules, don't inherit)
  - datetime for timestamps
  - json module for saving reports
"""

import json
from datetime import datetime
from urllib.parse import urlparse

from scanner.models import ScanReport
from scanner.header_checker import HeaderChecker
from scanner.ssl_checker import SSLChecker
from scanner.dir_scanner import DirectoryScanner


def normalize_target(target: str) -> str:
    """
    Ensure the target URL is valid and normalized.
    
    Examples:
        "example.com"          → "https://example.com"
        "http://example.com"   → "http://example.com"  (kept as-is, flagged by SSL checker)
        "  https://EXAMPLE.com " → "https://example.com"
    """
    target = target.strip()
    
    # If no scheme, default to HTTPS
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    # Lowercase the scheme and host (URLs are case-insensitive for host)
    parsed = urlparse(target)
    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower()
    )
    return normalized.geturl()


def validate_target(target: str) -> tuple[bool, str]:
    """
    Basic validation before scanning.
    
    Returns:
        (True, "") if valid
        (False, error_message) if invalid
    """
    try:
        parsed = urlparse(target)
        if not parsed.scheme or not parsed.netloc:
            return False, "Invalid URL — missing scheme or hostname"
        if parsed.scheme not in ("http", "https"):
            return False, f"Unsupported scheme '{parsed.scheme}' — use http:// or https://"
        if "." not in parsed.netloc and parsed.netloc not in ("localhost", "127.0.0.1"):
            return False, f"'{parsed.netloc}' doesn't look like a valid hostname"
        return True, ""
    except Exception as e:
        return False, str(e)


class SentinelCore:
    """
    The main scanner orchestrator.
    
    Usage:
        scanner = SentinelCore()
        report = scanner.scan("https://example.com")
        print(report.total_findings())
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        # Initialize all scanner modules
        # New modules can be added here without changing any other code
        self.modules = [
            HeaderChecker(timeout=timeout),
            SSLChecker(timeout=timeout),
            DirectoryScanner(timeout=timeout),
        ]

    def scan(self, target: str) -> ScanReport:
        """
        Run the complete security scan against a target.
        
        Args:
            target: URL to scan (with or without https://)
            
        Returns:
            ScanReport object with all findings from all modules
        """
        # Normalize and validate the target
        target = normalize_target(target)
        is_valid, error_msg = validate_target(target)
        
        if not is_valid:
            # Return an empty report with the validation error
            report = ScanReport(
                target=target,
                scan_time=datetime.utcnow().isoformat() + "Z",
                modules_run=[]
            )
            return report

        # Create the report container
        report = ScanReport(
            target=target,
            scan_time=datetime.utcnow().isoformat() + "Z",
            modules_run=[]
        )

        # Run each module and collect results
        for module in self.modules:
            module_result = module.check(target)
            report.results.append(module_result)
            report.modules_run.append(module_result.module_name)

        return report

    def save_json_report(self, report: ScanReport, output_path: str) -> str:
        """
        Serialize the report to a JSON file.
        
        The JSON format makes SentinelScan's output machine-readable,
        so it can integrate with other security tools, dashboards, or CI/CD pipelines.
        
        Args:
            report:      The completed ScanReport
            output_path: Where to save the JSON file
            
        Returns:
            The path where the file was saved
        """
        def serialize(obj):
            """Helper to convert non-JSON-serializable objects like Enums."""
            if hasattr(obj, "value"):   # Enum → use its string value
                return obj.value
            if hasattr(obj, "__dict__"):  # Dataclass → use its dict
                return obj.__dict__
            return str(obj)

        report_dict = {
            "sentinelscan_version": "1.0",
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
            "modules": []
        }

        for result in report.results:
            module_data = {
                "module": result.module_name,
                "target": result.target,
                "error": result.error,
                "findings": [
                    {
                        "title": f.title,
                        "severity": f.severity.value,
                        "cvss_score": f.cvss_score,
                        "description": f.description,
                        "recommendation": f.recommendation,
                        "evidence": f.evidence,
                    }
                    for f in result.findings
                ],
                "passed_checks": result.passed
            }
            report_dict["modules"].append(module_data)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, default=serialize)

        return output_path
