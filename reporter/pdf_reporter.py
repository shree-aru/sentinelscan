"""
SentinelScan - Professional PDF Report Generator
==================================================
Generates a full security assessment PDF report from a completed scan.

This is what separates SentinelScan from command-line-only tools.
A PDF report is what security consultants deliver to clients.
It communicates findings to non-technical stakeholders (managers, CISOs)
who won't read terminal output.

PDF structure:
  Page 1  - Cover page (target, risk rating, date)
  Page 2  - Executive Summary (findings table, modules, duration)
  Page 3+ - Detailed findings per module (title, severity, evidence, fix)
  Last    - Footer on every page

Library used: fpdf2 (already in requirements.txt)
  fpdf2 is the modern fork of PyFPDF — no external dependencies,
  generates PDFs programmatically without LaTeX or browser engines.

Learning goals:
  - Object-oriented design (class inheriting from FPDF)
  - Method decomposition (each section is its own method)
  - Color theory in code (RGB values for visual hierarchy)
  - Page layout concepts (margins, coordinates, line heights)
  - Working with fonts and text metrics in a fixed-size canvas
"""

from datetime import datetime
from fpdf import FPDF

from scanner.models import ScanReport, ModuleResult, Finding, Severity


# ─────────────────────────────────────────────────────────────────────────────
#  COLOR PALETTE
#  Consistent colors used throughout the report
# ─────────────────────────────────────────────────────────────────────────────
class Colors:
    # Brand
    NAVY          = (10,  25,  60)    # Dark navy — headers, titles
    ACCENT_BLUE   = (37,  99,  235)   # Bright blue — links, highlights
    LIGHT_BLUE_BG = (239, 246, 255)   # Very light blue — alternating rows

    # Severity
    CRITICAL      = (185, 28,  28)    # Deep red
    CRITICAL_BG   = (254, 226, 226)   # Light red background
    HIGH          = (194, 65,  12)    # Deep orange
    HIGH_BG       = (255, 237, 213)   # Light orange background
    MEDIUM        = (161, 98,  7)     # Amber
    MEDIUM_BG     = (254, 249, 195)   # Light yellow background
    LOW           = (29,  78,  216)   # Blue
    LOW_BG        = (219, 234, 254)   # Light blue background
    INFO          = (107, 114, 128)   # Gray
    INFO_BG       = (243, 244, 246)   # Light gray background
    PASSED        = (21,  128, 61)    # Green

    # Text
    DARK_TEXT     = (17,  24,  39)    # Almost black
    BODY_TEXT     = (55,  65,  81)    # Dark gray
    MUTED_TEXT    = (107, 114, 128)   # Medium gray
    WHITE         = (255, 255, 255)


def _severity_colors(severity: Severity) -> tuple:
    """Return (text_color, background_color) for a given severity."""
    mapping = {
        Severity.CRITICAL: (Colors.CRITICAL, Colors.CRITICAL_BG),
        Severity.HIGH:     (Colors.HIGH,     Colors.HIGH_BG),
        Severity.MEDIUM:   (Colors.MEDIUM,   Colors.MEDIUM_BG),
        Severity.LOW:      (Colors.LOW,      Colors.LOW_BG),
        Severity.INFO:     (Colors.INFO,     Colors.INFO_BG),
    }
    return mapping.get(severity, (Colors.INFO, Colors.INFO_BG))


class SentinelPDF(FPDF):
    """
    Custom PDF class extending FPDF with SentinelScan branding.

    By inheriting from FPDF and overriding header() and footer(),
    every page automatically gets the nav bar and footer.
    This is the standard pattern for branded PDF documents in fpdf2.
    """

    def __init__(self, report: ScanReport):
        super().__init__()
        self.report = report
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(left=15, top=20, right=15)

    def header(self):
        """Runs automatically at the top of EVERY page."""
        if self.page_no() == 1:
            return  # Cover page has its own full-page design

        # Top bar
        self.set_fill_color(*Colors.NAVY)
        self.rect(0, 0, 210, 13, 'F')

        # Left: tool name
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*Colors.WHITE)
        self.set_xy(10, 4)
        self.cell(0, 5, "SentinelScan Security Report -- Confidential", 0, 0, "L")

        # Right: page number
        self.set_xy(10, 4)
        self.cell(0, 5, f"Page {self.page_no()}", 0, 0, "R")

        self.set_y(17)

    def footer(self):
        """Runs automatically at the bottom of every page."""
        self.set_y(-12)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(*Colors.MUTED_TEXT)
        self.cell(
            0, 8,
            "SentinelScan v2.0  |  For Authorized Security Testing Only  |  "
            "github.com/shree-aru/sentinelscan",
            0, 0, "C"
        )

    # ─────────────────────────────────────────────────────────────────────────
    #  COVER PAGE
    # ─────────────────────────────────────────────────────────────────────────

    def add_cover_page(self):
        """Full-page branded cover."""
        self.add_page()

        # Full navy background top section (60% of page)
        self.set_fill_color(*Colors.NAVY)
        self.rect(0, 0, 210, 148, 'F')

        # Tool name — large white text
        self.set_font("Helvetica", "B", 32)
        self.set_text_color(*Colors.WHITE)
        self.set_xy(0, 45)
        self.cell(210, 14, "SENTINELSCAN", 0, 1, "C")

        # Subtitle
        self.set_font("Helvetica", "", 13)
        self.set_text_color(180, 200, 255)
        self.set_xy(0, 60)
        self.cell(210, 8, "Web Security Assessment Report", 0, 1, "C")

        # Thin accent line
        self.set_draw_color(37, 99, 235)
        self.set_line_width(0.8)
        self.line(55, 72, 155, 72)

        # Target URL
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(200, 220, 255)
        self.set_xy(0, 78)
        self.cell(210, 6, "Target", 0, 1, "C")
        self.set_font("Helvetica", "", 12)
        self.set_text_color(*Colors.WHITE)
        self.set_xy(0, 85)
        # Truncate very long URLs for display
        target_display = self.report.target
        if len(target_display) > 60:
            target_display = target_display[:57] + "..."
        self.cell(210, 7, target_display, 0, 1, "C")

        # Date
        self.set_font("Helvetica", "", 9)
        self.set_text_color(160, 185, 255)
        scan_dt = self.report.scan_time[:10]
        self.set_xy(0, 100)
        self.cell(210, 6, f"Scan Date: {scan_dt}", 0, 1, "C")

        # ── Risk Rating Badge ────────────────────────────────────────────────
        risk = self.report.risk_rating()
        risk_color = {
            "CRITICAL": Colors.CRITICAL,
            "HIGH":     Colors.HIGH,
            "MEDIUM":   Colors.MEDIUM,
            "LOW":      Colors.LOW,
            "SECURE":   Colors.PASSED,
        }.get(risk, Colors.INFO)

        # Badge background
        self.set_fill_color(*risk_color)
        self.round_clip = False
        self.rect(70, 112, 70, 22, 'F')

        # Badge text
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(*Colors.WHITE)
        self.set_xy(70, 116)
        self.cell(70, 14, risk, 0, 0, "C")

        # Risk label above badge
        self.set_font("Helvetica", "", 8)
        self.set_text_color(160, 185, 255)
        self.set_xy(0, 108)
        self.cell(210, 5, "Overall Risk Rating", 0, 1, "C")

        # ── White bottom section of cover ────────────────────────────────────
        self.set_fill_color(*Colors.WHITE)
        self.rect(0, 148, 210, 149, 'F')

        # Quick stats in the white section
        findings_by_sev = self.report.findings_by_severity()
        stats = [
            ("CRITICAL", self.report.critical_count(), Colors.CRITICAL),
            ("HIGH",     self.report.high_count(),     Colors.HIGH),
            ("MEDIUM",   self.report.medium_count(),   Colors.MEDIUM),
            ("LOW",      self.report.low_count(),      Colors.LOW),
        ]

        box_w = 40
        start_x = (210 - (box_w * 4 + 10 * 3)) / 2
        y = 162

        for i, (label, count, color) in enumerate(stats):
            x = start_x + i * (box_w + 10)
            # Box border
            self.set_draw_color(*color)
            self.set_fill_color(*Colors.WHITE)
            self.set_line_width(1.2)
            self.rect(x, y, box_w, 28, 'D')
            # Count
            self.set_font("Helvetica", "B", 22)
            self.set_text_color(*color)
            self.set_xy(x, y + 2)
            self.cell(box_w, 18, str(count), 0, 0, "C")
            # Label
            self.set_font("Helvetica", "", 7)
            self.set_text_color(*Colors.MUTED_TEXT)
            self.set_xy(x, y + 20)
            self.cell(box_w, 6, label, 0, 0, "C")

        # Modules count
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*Colors.BODY_TEXT)
        self.set_xy(0, 200)
        self.cell(210, 7, f"Scan ran {len(self.report.modules_run)} modules across 6 security domains", 0, 1, "C")

        # Bottom disclaimer
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*Colors.MUTED_TEXT)
        self.set_xy(0, 268)
        self.cell(210, 5, "CONFIDENTIAL -- For authorized security testing and remediation purposes only", 0, 1, "C")

    # ─────────────────────────────────────────────────────────────────────────
    #  EXECUTIVE SUMMARY PAGE
    # ─────────────────────────────────────────────────────────────────────────

    def add_executive_summary(self):
        """Page 2: High-level summary table and scan metadata."""
        self.add_page()

        # Page title
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(*Colors.NAVY)
        self.cell(0, 10, "Executive Summary", 0, 1, "L")
        self.set_draw_color(*Colors.ACCENT_BLUE)
        self.set_line_width(0.5)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(5)

        # ── Scan Metadata ───────────────────────────────────────────────────
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*Colors.DARK_TEXT)
        self.cell(0, 7, "Scan Information", 0, 1)
        self.ln(1)

        meta = [
            ("Target",       self.report.target),
            ("Scan Time",    self.report.scan_time.replace("T", "  ").replace("Z", " UTC")),
            ("Overall Risk", self.report.risk_rating()),
            ("Total Findings", str(self.report.total_findings())),
            ("Modules Run",  ", ".join(self.report.modules_run[:4]) +
                             (f" + {len(self.report.modules_run)-4} more"
                              if len(self.report.modules_run) > 4 else "")),
        ]

        # Alternating row table
        row_h = 7
        for i, (label, value) in enumerate(meta):
            if i % 2 == 0:
                self.set_fill_color(*Colors.LIGHT_BLUE_BG)
            else:
                self.set_fill_color(*Colors.WHITE)

            self.set_font("Helvetica", "B", 9)
            self.set_text_color(*Colors.BODY_TEXT)
            self.cell(45, row_h, f"  {label}", 0, 0, "L", fill=True)

            self.set_font("Helvetica", "", 9)
            self.set_text_color(*Colors.DARK_TEXT)
            # Value cell (needs to handle long URLs — truncate)
            val_display = value if len(value) <= 95 else value[:92] + "..."
            self.cell(0, row_h, val_display, 0, 1, "L", fill=True)

        self.ln(8)

        # ── Findings Breakdown Table ─────────────────────────────────────────
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*Colors.DARK_TEXT)
        self.cell(0, 7, "Vulnerability Breakdown", 0, 1)
        self.ln(1)

        # Table header
        self.set_fill_color(*Colors.NAVY)
        self.set_text_color(*Colors.WHITE)
        self.set_font("Helvetica", "B", 9)
        col_w = [35, 20, 40, 85]
        headers_row = ["Severity", "Count", "CVSS Range", "Recommended Action"]
        for w, h in zip(col_w, headers_row):
            self.cell(w, 8, f"  {h}", 0, 0, "L", fill=True)
        self.ln()

        # Table rows
        severity_rows = [
            (Severity.CRITICAL, self.report.critical_count(), "9.0 - 10.0", "Fix immediately -- active threat risk"),
            (Severity.HIGH,     self.report.high_count(),     "7.0 - 8.9",  "Fix within 7 days"),
            (Severity.MEDIUM,   self.report.medium_count(),   "4.0 - 6.9",  "Fix within 30 days"),
            (Severity.LOW,      self.report.low_count(),      "0.1 - 3.9",  "Fix when possible"),
        ]

        for sev, count, cvss_range, action in severity_rows:
            text_color, bg_color = _severity_colors(sev)
            self.set_fill_color(*bg_color)
            self.set_text_color(*text_color)
            self.set_font("Helvetica", "B", 9)
            self.cell(col_w[0], 8, f"  {sev.value}", 0, 0, "L", fill=True)
            self.cell(col_w[1], 8, f"  {count}", 0, 0, "C", fill=True)
            self.set_text_color(*Colors.BODY_TEXT)
            self.set_font("Helvetica", "", 9)
            self.cell(col_w[2], 8, f"  {cvss_range}", 0, 0, "L", fill=True)
            self.cell(col_w[3], 8, f"  {action}", 0, 0, "L", fill=True)
            self.ln()

        # Total row
        self.set_fill_color(*Colors.NAVY)
        self.set_text_color(*Colors.WHITE)
        self.set_font("Helvetica", "B", 9)
        self.cell(col_w[0], 8, "  TOTAL", 0, 0, "L", fill=True)
        self.cell(col_w[1], 8, f"  {self.report.total_findings()}", 0, 0, "C", fill=True)
        self.cell(col_w[2] + col_w[3], 8, "", 0, 0, "L", fill=True)
        self.ln(12)

        # ── Risk Explanation Box ─────────────────────────────────────────────
        risk = self.report.risk_rating()
        risk_text_color, risk_bg = _severity_colors(
            Severity[risk] if risk in Severity.__members__ else Severity.INFO
        )
        self.set_fill_color(*risk_bg)
        self.set_draw_color(*risk_text_color)
        self.set_line_width(0.5)

        box_y = self.get_y()
        # Box drawn after content to know height
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*risk_text_color)
        self.cell(0, 7, f"  Overall Risk: {risk}", 0, 1, "L", fill=True)

        risk_explanations = {
            "CRITICAL": "One or more critical vulnerabilities were found that pose an immediate risk of data breach or system compromise. These must be addressed before the system handles any sensitive data.",
            "HIGH":     "High severity vulnerabilities were detected. While not immediately exploitable in all cases, these represent significant security gaps that should be resolved within a week.",
            "MEDIUM":   "Medium severity issues were found. These represent meaningful risks that should be scheduled for remediation within 30 days.",
            "LOW":      "Only low severity issues were detected. These are informational or minor configuration improvements with limited immediate risk.",
            "SECURE":   "No significant vulnerabilities were detected in the modules scanned. Continue regular security assessments to maintain this posture.",
        }

        self.set_font("Helvetica", "", 9)
        self.set_text_color(*Colors.BODY_TEXT)
        self.set_fill_color(*risk_bg)
        self.multi_cell(0, 5, f"  {risk_explanations.get(risk, '')}", 0, "L", fill=True)

    # ─────────────────────────────────────────────────────────────────────────
    #  DETAILED FINDINGS PAGES
    # ─────────────────────────────────────────────────────────────────────────

    def add_findings_pages(self):
        """One section per module, with all findings from that module."""
        for module_result in self.report.results:
            if not module_result.findings and not module_result.passed:
                continue

            self.add_page()
            self._module_header(module_result.module_name, len(module_result.findings))

            # Module error
            if module_result.error:
                self.set_font("Helvetica", "I", 9)
                self.set_text_color(*Colors.HIGH)
                self.multi_cell(0, 5, f"Module error: {module_result.error}", 0, "L")
                self.ln(3)

            # Findings
            for finding in module_result.findings:
                self._finding_block(finding)

            # Passed checks
            if module_result.passed:
                self.ln(3)
                self.set_font("Helvetica", "B", 9)
                self.set_text_color(*Colors.PASSED)
                self.cell(0, 6, "Passed Checks", 0, 1)

                for check in module_result.passed:
                    self.set_font("Helvetica", "", 8)
                    self.set_text_color(*Colors.BODY_TEXT)
                    # Truncate long passed check text
                    check_display = check if len(check) <= 130 else check[:127] + "..."
                    self.cell(5, 5, "", 0, 0)  # indent
                    self.multi_cell(0, 5, f"+ {check_display}", 0, "L")

    def _module_header(self, module_name: str, finding_count: int):
        """Section header for each module."""
        # Colored module bar
        self.set_fill_color(*Colors.NAVY)
        self.set_text_color(*Colors.WHITE)
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 10, f"  {module_name}", 0, 0, "L", fill=True)

        # Finding count badge
        badge_text = f"{finding_count} issue{'s' if finding_count != 1 else ''}"
        badge_color = Colors.CRITICAL if finding_count > 0 else Colors.PASSED
        self.set_fill_color(*badge_color)
        self.set_text_color(*Colors.WHITE)
        self.set_font("Helvetica", "B", 8)
        # Move to end of line to place badge
        self.set_xy(self.get_x() - 35, self.get_y())
        self.cell(35, 10, badge_text, 0, 1, "C", fill=True)
        self.ln(3)

    def _finding_block(self, finding: Finding):
        """
        Render a single finding as a styled block.
        Each block has: severity badge, title, CVSS, description, evidence, fix.
        """
        text_color, bg_color = _severity_colors(finding.severity)

        # Auto page break check — if less than 50mm left, start new page
        if self.get_y() > 245:
            self.add_page()

        block_start_y = self.get_y()

        # ── Title bar with severity badge ────────────────────────────────────
        self.set_fill_color(*bg_color)
        self.set_text_color(*text_color)
        self.set_font("Helvetica", "B", 8)
        severity_w = 22
        self.cell(severity_w, 8, f"  {finding.severity.value}", 0, 0, "L", fill=True)

        # CVSS score
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*Colors.MUTED_TEXT)
        self.set_fill_color(*Colors.WHITE)
        self.cell(22, 8, f"CVSS {finding.cvss_score:.1f}", 0, 0, "L")

        # Title
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*Colors.DARK_TEXT)
        title_display = finding.title if len(finding.title) <= 90 else finding.title[:87] + "..."
        self.cell(0, 8, title_display, 0, 1, "L")

        # ── Description ──────────────────────────────────────────────────────
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*Colors.BODY_TEXT)
        self.set_x(15 + 5)  # indent
        desc_display = finding.description.replace("\n", " ")
        if len(desc_display) > 600:
            desc_display = desc_display[:597] + "..."
        self.multi_cell(0, 4.5, desc_display, 0, "L")
        self.ln(1)

        # ── Evidence ─────────────────────────────────────────────────────────
        if finding.evidence:
            self.set_x(15 + 5)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*Colors.MUTED_TEXT)
            self.cell(18, 4.5, "Evidence:", 0, 0)
            self.set_font("Helvetica", "", 8)
            evidence_display = finding.evidence if len(finding.evidence) <= 120 else finding.evidence[:117] + "..."
            self.set_text_color(*Colors.BODY_TEXT)
            self.multi_cell(0, 4.5, evidence_display, 0, "L")
            self.ln(1)

        # ── Recommendation ────────────────────────────────────────────────────
        self.set_x(15 + 5)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*Colors.PASSED)
        self.cell(20, 4.5, "Fix:", 0, 0)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*Colors.BODY_TEXT)
        # Only first line of recommendation in the list (keep it tight)
        rec_first_line = finding.recommendation.split("\n")[0]
        if len(rec_first_line) > 150:
            rec_first_line = rec_first_line[:147] + "..."
        self.multi_cell(0, 4.5, rec_first_line, 0, "L")

        # Bottom spacing + thin separator line
        self.ln(2)
        self.set_draw_color(220, 220, 220)
        self.set_line_width(0.2)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(3)


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC INTERFACE
# ─────────────────────────────────────────────────────────────────────────────

def generate_pdf_report(report: ScanReport, output_path: str) -> str:
    """
    Generate a complete PDF security report from a ScanReport.

    Args:
        report:      Completed ScanReport from SentinelCore.scan()
        output_path: File path where the PDF will be saved (e.g., 'report.pdf')

    Returns:
        The output_path where the file was saved

    Usage:
        from reporter.pdf_reporter import generate_pdf_report
        generate_pdf_report(report, "sentinelscan_report.pdf")
    """
    pdf = SentinelPDF(report)

    # Build the PDF section by section
    pdf.add_cover_page()
    pdf.add_executive_summary()
    pdf.add_findings_pages()

    # Write to disk
    pdf.output(output_path)
    return output_path
