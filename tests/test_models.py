"""
Tests for scanner/models.py — the data layer.

These are unit tests: they test one thing in isolation, with no
network, no files, no external state. Each test must be reproducible
and pass deterministically every time it runs.

Run with: python -m pytest tests/ -v
"""

import pytest
from scanner.models import ScanReport, ModuleResult, Finding, Severity


# ─────────────────────────────────────────────────────────────────────────────
#  Helper factory functions
#  These make tests shorter and more readable.
# ─────────────────────────────────────────────────────────────────────────────

def make_report(*severities) -> ScanReport:
    """Create a ScanReport with one finding per given severity."""
    report = ScanReport(target="https://test.com", scan_time="2026-01-01T00:00:00Z")
    for sev in severities:
        m = ModuleResult(module_name=f"Module-{sev.value}", target="https://test.com")
        m.findings.append(Finding(
            title=f"{sev.value} finding",
            severity=sev,
            description="Test description",
            recommendation="Test recommendation",
            cvss_score=5.0,
        ))
        report.results.append(m)
    return report


# ─────────────────────────────────────────────────────────────────────────────
#  ScanReport — risk rating logic
# ─────────────────────────────────────────────────────────────────────────────

class TestRiskRating:

    def test_empty_report_is_secure(self):
        """A report with no findings should rate as SECURE."""
        report = ScanReport(target="https://test.com", scan_time="2026-01-01T00:00:00Z")
        assert report.risk_rating() == "SECURE"

    def test_single_critical_finding(self):
        report = make_report(Severity.CRITICAL)
        assert report.risk_rating() == "CRITICAL"

    def test_single_high_finding(self):
        report = make_report(Severity.HIGH)
        assert report.risk_rating() == "HIGH"

    def test_single_medium_finding(self):
        report = make_report(Severity.MEDIUM)
        assert report.risk_rating() == "MEDIUM"

    def test_single_low_finding(self):
        report = make_report(Severity.LOW)
        assert report.risk_rating() == "LOW"

    def test_critical_dominates_over_lower(self):
        """CRITICAL should win even if there are also HIGH, MEDIUM, LOW findings."""
        report = make_report(Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
        assert report.risk_rating() == "CRITICAL"

    def test_high_dominates_over_medium_and_low(self):
        report = make_report(Severity.LOW, Severity.MEDIUM, Severity.HIGH)
        assert report.risk_rating() == "HIGH"

    def test_info_only_is_secure(self):
        """INFO findings should not affect the risk rating."""
        report = make_report(Severity.INFO)
        assert report.risk_rating() == "SECURE"


# ─────────────────────────────────────────────────────────────────────────────
#  ScanReport — severity counts
# ─────────────────────────────────────────────────────────────────────────────

class TestSeverityCounts:

    def test_zero_counts_on_empty_report(self):
        report = ScanReport(target="https://test.com", scan_time="2026-01-01T00:00:00Z")
        assert report.critical_count() == 0
        assert report.high_count() == 0
        assert report.medium_count() == 0
        assert report.low_count() == 0
        assert report.total_findings() == 0

    def test_counts_sum_correctly(self):
        report = make_report(
            Severity.CRITICAL, Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM, Severity.MEDIUM, Severity.MEDIUM,
        )
        assert report.critical_count() == 2
        assert report.high_count() == 1
        assert report.medium_count() == 3
        assert report.low_count() == 0
        assert report.total_findings() == 6

    def test_counts_across_multiple_modules(self):
        """Findings from different modules should all be counted."""
        report = ScanReport(target="https://test.com", scan_time="2026-01-01T00:00:00Z")
        for i in range(3):
            m = ModuleResult(module_name=f"Module-{i}", target="https://test.com")
            m.findings.append(Finding(
                title=f"Finding {i}", severity=Severity.HIGH,
                description="d", recommendation="r"
            ))
            report.results.append(m)
        assert report.high_count() == 3
        assert report.total_findings() == 3

    def test_info_not_counted_in_total(self):
        """INFO findings count toward total_findings but not risk rating."""
        report = make_report(Severity.INFO)
        assert report.total_findings() == 1
        assert report.risk_rating() == "SECURE"


# ─────────────────────────────────────────────────────────────────────────────
#  Finding — data validation
# ─────────────────────────────────────────────────────────────────────────────

class TestFinding:

    def test_finding_default_cvss_is_zero(self):
        f = Finding(
            title="Test",
            severity=Severity.LOW,
            description="desc",
            recommendation="rec"
        )
        assert f.cvss_score == 0.0

    def test_finding_default_evidence_is_empty(self):
        f = Finding(title="T", severity=Severity.INFO, description="d", recommendation="r")
        assert f.evidence == ""

    def test_severity_enum_values(self):
        """Enum values should be the strings used in JSON output."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"


# ─────────────────────────────────────────────────────────────────────────────
#  ModuleResult
# ─────────────────────────────────────────────────────────────────────────────

class TestModuleResult:

    def test_module_result_defaults(self):
        result = ModuleResult(module_name="Test Module", target="https://test.com")
        assert result.findings == []
        assert result.passed == []
        assert result.error == ""

    def test_module_result_with_error(self):
        result = ModuleResult(module_name="Test", target="https://test.com")
        result.error = "Connection refused"
        assert result.error == "Connection refused"
        assert result.findings == []

    def test_findings_by_severity_grouping(self):
        """findings_by_severity() should group all findings correctly."""
        report = make_report(Severity.HIGH, Severity.HIGH, Severity.MEDIUM)
        grouped = report.findings_by_severity()
        assert len(grouped[Severity.HIGH]) == 2
        assert len(grouped[Severity.MEDIUM]) == 1
        assert len(grouped[Severity.CRITICAL]) == 0
        assert len(grouped[Severity.LOW]) == 0
