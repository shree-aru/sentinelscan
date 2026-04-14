"""
SentinelScan - Data Models
===========================
Defines the core data structures used across all scanner modules.
Every scan result, every finding, every severity level lives here.

Learning: This is called a "data layer" - separating your data 
structures from your logic is professional software engineering.
"""

from dataclasses import dataclass, field
from typing import List
from enum import Enum


class Severity(Enum):
    """
    Vulnerability severity classification.
    Based on CVSS (Common Vulnerability Scoring System) — the 
    industry standard used by Microsoft, Google, and every major company.
    
    CRITICAL  : CVSS 9.0–10.0  → Fix immediately
    HIGH      : CVSS 7.0–8.9   → Fix within 7 days
    MEDIUM    : CVSS 4.0–6.9   → Fix within 30 days
    LOW       : CVSS 0.1–3.9   → Fix when possible
    INFO      : CVSS 0.0       → Informational only
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """
    Represents a single vulnerability or security finding.
    
    Every issue we detect becomes a Finding object.
    Think of this like a bug report — structured and clear.
    """
    title: str              # Short name of the vulnerability
    severity: Severity      # How dangerous is it?
    description: str        # What is the risk? Why does it matter?
    recommendation: str     # How to fix it?
    cvss_score: float = 0.0 # Numeric score (0.0 to 10.0)
    evidence: str = ""      # Proof — what did we actually see?


@dataclass
class ModuleResult:
    """
    The result from one scanner module (e.g., HeaderChecker, SSLChecker).
    
    Each module returns one ModuleResult containing:
    - All findings (problems we found)
    - All passed checks (things that are correctly configured)
    """
    module_name: str                              # e.g., "Security Headers"
    target: str                                   # The URL that was scanned
    findings: List[Finding] = field(default_factory=list)  # Problems found
    passed: List[str] = field(default_factory=list)        # Things that passed
    error: str = ""                               # If module itself failed


@dataclass
class ScanReport:
    """
    The complete scan report for a full target.
    
    Aggregates results from ALL modules into one final report.
    This is what gets written to JSON / PDF.
    """
    target: str
    scan_time: str
    modules_run: List[str] = field(default_factory=list)
    results: List[ModuleResult] = field(default_factory=list)

    def total_findings(self) -> int:
        """Count total vulnerabilities found across all modules."""
        return sum(len(r.findings) for r in self.results)

    def findings_by_severity(self) -> dict:
        """Group all findings by severity level."""
        grouped = {s: [] for s in Severity}
        for result in self.results:
            for finding in result.findings:
                grouped[finding.severity].append(finding)
        return grouped

    def critical_count(self) -> int:
        return len(self.findings_by_severity()[Severity.CRITICAL])

    def high_count(self) -> int:
        return len(self.findings_by_severity()[Severity.HIGH])

    def medium_count(self) -> int:
        return len(self.findings_by_severity()[Severity.MEDIUM])

    def low_count(self) -> int:
        return len(self.findings_by_severity()[Severity.LOW])

    def risk_rating(self) -> str:
        """
        Calculate overall risk rating for the target.
        Based on the most severe finding present.
        """
        if self.critical_count() > 0:
            return "CRITICAL"
        elif self.high_count() > 0:
            return "HIGH"
        elif self.medium_count() > 0:
            return "MEDIUM"
        elif self.low_count() > 0:
            return "LOW"
        else:
            return "SECURE"
