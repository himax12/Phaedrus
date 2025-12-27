"""
Forensic Report Generator - ISO/IEC 27037 Compliant.

Generates court-ready PDF reports using Jinja2 templates and WeasyPrint.

Report Structure (ISO 27037):
1. Executive Summary
2. Incident Overview
3. Evidence Provenance (Chain of Custody)
4. Timeline of Events
5. AI/ML Analysis Results
6. SHAP Explanations
7. Conclusions & Recommendations
8. Appendices
"""

import base64
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

# WeasyPrint import with graceful fallback
try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False


@dataclass
class TimelineEvent:
    """An event in the incident timeline."""

    timestamp: datetime
    description: str
    severity: str = "INFO"
    source: str | None = None
    log_id: str | None = None


@dataclass
class EvidenceItem:
    """A piece of evidence with chain of custody."""

    evidence_id: str
    description: str
    source: str
    collected_at: datetime
    hash_value: str
    hash_algorithm: str = "SHA-256"
    block_id: int | None = None
    merkle_root: str | None = None


@dataclass
class AIAnalysisResult:
    """Results from AI analysis."""

    log_id: str
    anomaly_score: float
    is_anomaly: bool
    method: str
    explanation: str
    top_features: list[dict[str, Any]] = field(default_factory=list)
    shap_plot_base64: str | None = None


@dataclass
class ForensicReport:
    """Complete forensic investigation report."""

    # Report metadata
    report_id: str
    title: str
    generated_at: datetime
    generated_by: str
    case_number: str | None = None

    # Investigation details
    incident_start: datetime | None = None
    incident_end: datetime | None = None
    incident_summary: str = ""

    # Evidence
    evidence_items: list[EvidenceItem] = field(default_factory=list)
    chain_verification: dict[str, Any] | None = None

    # Timeline
    timeline: list[TimelineEvent] = field(default_factory=list)

    # AI Analysis
    ai_results: list[AIAnalysisResult] = field(default_factory=list)
    attack_paths: list[dict[str, Any]] = field(default_factory=list)

    # Conclusions
    conclusions: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    # Appendices
    appendices: list[dict[str, Any]] = field(default_factory=list)


class ReportGenerator:
    """
    Generate ISO 27037 compliant forensic reports.

    Supports HTML and PDF output using Jinja2 and WeasyPrint.
    """

    # Default HTML template (embedded for portability)
    DEFAULT_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ report.title }}</title>
    <style>
        :root {
            --primary: #1a365d;
            --secondary: #2d3748;
            --accent: #3182ce;
            --danger: #e53e3e;
            --warning: #dd6b20;
            --success: #38a169;
            --background: #f7fafc;
            --text: #2d3748;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: var(--text);
            background: var(--background);
        }

        .container {
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem;
            background: white;
        }

        /* Header */
        .report-header {
            text-align: center;
            padding: 2rem;
            border-bottom: 3px solid var(--primary);
            margin-bottom: 2rem;
        }

        .report-header h1 {
            color: var(--primary);
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }

        .report-meta {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
            text-align: left;
            margin-top: 1rem;
            padding: 1rem;
            background: var(--background);
            border-radius: 8px;
        }

        .meta-item {
            display: flex;
            gap: 0.5rem;
        }

        .meta-label {
            font-weight: 600;
            color: var(--secondary);
        }

        /* Sections */
        section {
            margin: 2rem 0;
            page-break-inside: avoid;
        }

        section h2 {
            color: var(--primary);
            border-bottom: 2px solid var(--accent);
            padding-bottom: 0.5rem;
            margin-bottom: 1rem;
        }

        section h3 {
            color: var(--secondary);
            margin: 1rem 0 0.5rem;
        }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            font-size: 0.9rem;
        }

        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }

        th {
            background: var(--primary);
            color: white;
        }

        tr:nth-child(even) { background: var(--background); }
        tr:hover { background: #edf2f7; }

        /* Timeline */
        .timeline {
            position: relative;
            padding-left: 2rem;
        }

        .timeline::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 2px;
            background: var(--accent);
        }

        .timeline-event {
            position: relative;
            padding: 1rem;
            margin-bottom: 1rem;
            background: var(--background);
            border-radius: 8px;
            border-left: 3px solid var(--accent);
        }

        .timeline-event::before {
            content: '';
            position: absolute;
            left: -2.4rem;
            top: 1.2rem;
            width: 10px;
            height: 10px;
            background: var(--accent);
            border-radius: 50%;
        }

        .timeline-event.severity-critical { border-left-color: var(--danger); }
        .timeline-event.severity-critical::before { background: var(--danger); }
        .timeline-event.severity-error { border-left-color: var(--warning); }
        .timeline-event.severity-error::before { background: var(--warning); }

        .event-time {
            font-size: 0.85rem;
            color: #718096;
            margin-bottom: 0.25rem;
        }

        /* Anomaly cards */
        .anomaly-card {
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            background: white;
        }

        .anomaly-card.is-anomaly {
            border-left: 4px solid var(--danger);
        }

        .anomaly-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }

        .anomaly-score {
            font-size: 1.5rem;
            font-weight: bold;
        }

        .score-high { color: var(--danger); }
        .score-medium { color: var(--warning); }
        .score-low { color: var(--success); }

        .feature-bar {
            display: flex;
            align-items: center;
            margin: 0.25rem 0;
        }

        .feature-name {
            width: 150px;
            font-size: 0.85rem;
        }

        .feature-value {
            flex: 1;
            height: 20px;
            background: #e2e8f0;
            border-radius: 4px;
            overflow: hidden;
        }

        .feature-fill {
            height: 100%;
            transition: width 0.3s;
        }

        .feature-fill.positive { background: var(--danger); }
        .feature-fill.negative { background: var(--success); }

        /* SHAP plots */
        .shap-plot {
            text-align: center;
            margin: 1rem 0;
        }

        .shap-plot img {
            max-width: 100%;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
        }

        /* Evidence chain */
        .evidence-item {
            padding: 1rem;
            margin: 0.5rem 0;
            background: var(--background);
            border-radius: 8px;
            border-left: 3px solid var(--success);
        }

        .hash-value {
            font-family: monospace;
            font-size: 0.8rem;
            background: #edf2f7;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            word-break: break-all;
        }

        /* Conclusions */
        .conclusion-list, .recommendation-list {
            list-style: none;
            padding: 0;
        }

        .conclusion-list li, .recommendation-list li {
            padding: 0.75rem 1rem;
            margin: 0.5rem 0;
            background: var(--background);
            border-radius: 8px;
            border-left: 3px solid var(--primary);
        }

        .recommendation-list li {
            border-left-color: var(--accent);
        }

        /* Footer */
        .report-footer {
            margin-top: 3rem;
            padding-top: 1rem;
            border-top: 2px solid var(--primary);
            text-align: center;
            font-size: 0.85rem;
            color: #718096;
        }

        /* Print styles */
        @media print {
            body { background: white; }
            .container { max-width: 100%; padding: 0; }
            section { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="report-header">
            <h1>{{ report.title }}</h1>
            <p>Forensic Investigation Report</p>
            <div class="report-meta">
                <div class="meta-item">
                    <span class="meta-label">Report ID:</span>
                    <span>{{ report.report_id }}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Generated:</span>
                    <span>{{ report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Generated By:</span>
                    <span>{{ report.generated_by }}</span>
                </div>
                {% if report.case_number %}
                <div class="meta-item">
                    <span class="meta-label">Case Number:</span>
                    <span>{{ report.case_number }}</span>
                </div>
                {% endif %}
            </div>
        </header>

        <!-- Executive Summary / Incident Overview -->
        <section id="incident-overview">
            <h2>1. Incident Overview</h2>
            {% if report.incident_start and report.incident_end %}
            <p><strong>Incident Period:</strong> 
                {{ report.incident_start.strftime('%Y-%m-%d %H:%M') }} to 
                {{ report.incident_end.strftime('%Y-%m-%d %H:%M') }}
            </p>
            {% endif %}
            <p>{{ report.incident_summary }}</p>
        </section>

        <!-- Evidence Provenance -->
        <section id="evidence">
            <h2>2. Evidence Provenance</h2>
            <p>Chain of custody and cryptographic verification of collected evidence.</p>
            
            {% if report.chain_verification %}
            <h3>Chain Verification Status</h3>
            <div class="evidence-item" style="border-left-color: {{ 'var(--success)' if report.chain_verification.chain_intact else 'var(--danger)' }}">
                <strong>Status:</strong> {{ 'VERIFIED ✓' if report.chain_verification.chain_intact else 'VERIFICATION FAILED ✗' }}<br>
                <strong>Blocks Verified:</strong> {{ report.chain_verification.block_count }}<br>
                {% if report.chain_verification.errors %}
                <strong>Errors:</strong>
                <ul>
                    {% for error in report.chain_verification.errors %}
                    <li>{{ error }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
            </div>
            {% endif %}

            <h3>Evidence Items</h3>
            {% for item in report.evidence_items %}
            <div class="evidence-item">
                <strong>{{ item.evidence_id }}</strong>: {{ item.description }}<br>
                <strong>Source:</strong> {{ item.source }}<br>
                <strong>Collected:</strong> {{ item.collected_at.strftime('%Y-%m-%d %H:%M:%S') }}<br>
                <strong>{{ item.hash_algorithm }}:</strong> 
                <span class="hash-value">{{ item.hash_value }}</span>
                {% if item.merkle_root %}
                <br><strong>Merkle Root:</strong> 
                <span class="hash-value">{{ item.merkle_root }}</span>
                {% endif %}
            </div>
            {% endfor %}
        </section>

        <!-- Timeline -->
        <section id="timeline">
            <h2>3. Timeline of Events</h2>
            <div class="timeline">
                {% for event in report.timeline %}
                <div class="timeline-event severity-{{ event.severity|lower }}">
                    <div class="event-time">{{ event.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</div>
                    <div><strong>{{ event.severity }}</strong>: {{ event.description }}</div>
                    {% if event.source %}
                    <div style="font-size: 0.85rem; color: #718096;">Source: {{ event.source }}</div>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
        </section>

        <!-- AI Analysis -->
        <section id="ai-analysis">
            <h2>4. AI/ML Analysis Results</h2>
            <p>Automated anomaly detection and behavioral analysis results.</p>
            
            {% for result in report.ai_results %}
            <div class="anomaly-card {{ 'is-anomaly' if result.is_anomaly else '' }}">
                <div class="anomaly-header">
                    <div>
                        <strong>Log ID:</strong> {{ result.log_id }}<br>
                        <strong>Method:</strong> {{ result.method }}
                    </div>
                    <div class="anomaly-score {{ 'score-high' if result.anomaly_score > 0.7 else ('score-medium' if result.anomaly_score > 0.4 else 'score-low') }}">
                        {{ "%.2f"|format(result.anomaly_score) }}
                    </div>
                </div>
                <p>{{ result.explanation }}</p>
                
                {% if result.top_features %}
                <h4>Contributing Factors</h4>
                {% for feature in result.top_features %}
                <div class="feature-bar">
                    <span class="feature-name">{{ feature.name }}</span>
                    <div class="feature-value">
                        <div class="feature-fill {{ 'positive' if feature.contribution > 0 else 'negative' }}" 
                             style="width: {{ (feature.contribution|abs * 100)|min(100) }}%"></div>
                    </div>
                    <span style="width: 60px; text-align: right; font-size: 0.85rem;">
                        {{ "%+.3f"|format(feature.contribution) }}
                    </span>
                </div>
                {% endfor %}
                {% endif %}

                {% if result.shap_plot_base64 %}
                <div class="shap-plot">
                    <h4>SHAP Explanation</h4>
                    <img src="data:image/png;base64,{{ result.shap_plot_base64 }}" alt="SHAP Waterfall Plot">
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </section>

        <!-- Attack Paths -->
        {% if report.attack_paths %}
        <section id="attack-paths">
            <h2>5. Attack Path Analysis</h2>
            <table>
                <thead>
                    <tr>
                        <th>Entry Point</th>
                        <th>Target</th>
                        <th>Risk Score</th>
                        <th>Path Description</th>
                    </tr>
                </thead>
                <tbody>
                    {% for path in report.attack_paths %}
                    <tr>
                        <td>{{ path.entry_point }}</td>
                        <td>{{ path.target }}</td>
                        <td class="{{ 'score-high' if path.risk_score > 0.7 else ('score-medium' if path.risk_score > 0.4 else 'score-low') }}">
                            {{ "%.2f"|format(path.risk_score) }}
                        </td>
                        <td>{{ path.description }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
        {% endif %}

        <!-- Conclusions -->
        <section id="conclusions">
            <h2>6. Conclusions</h2>
            <ul class="conclusion-list">
                {% for conclusion in report.conclusions %}
                <li>{{ conclusion }}</li>
                {% endfor %}
            </ul>
        </section>

        <!-- Recommendations -->
        <section id="recommendations">
            <h2>7. Recommendations</h2>
            <ul class="recommendation-list">
                {% for rec in report.recommendations %}
                <li>{{ rec }}</li>
                {% endfor %}
            </ul>
        </section>

        <!-- Footer -->
        <footer class="report-footer">
            <p>Generated by Forensic Framework v1.0 | ISO/IEC 27037 Compliant</p>
            <p>This report contains sensitive forensic evidence. Handle according to your organization's security policies.</p>
        </footer>
    </div>
</body>
</html>'''

    def __init__(
        self,
        template_dir: Path | None = None,
        output_dir: Path | None = None,
    ):
        """
        Initialize report generator.

        Args:
            template_dir: Directory containing Jinja2 templates
            output_dir: Directory to save generated reports
        """
        self.template_dir = template_dir
        self.output_dir = output_dir or Path("./reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Setup Jinja2 environment
        if template_dir and template_dir.exists():
            self.env = Environment(
                loader=FileSystemLoader(str(template_dir)),
                autoescape=select_autoescape(["html", "xml"]),
            )
        else:
            # Use default embedded template
            self.env = Environment(autoescape=select_autoescape(["html", "xml"]))

    def generate_html(self, report: ForensicReport) -> str:
        """
        Generate HTML report.

        Args:
            report: ForensicReport data

        Returns:
            HTML string
        """
        if self.template_dir and (self.template_dir / "iso27037_report.html").exists():
            template = self.env.get_template("iso27037_report.html")
        else:
            template = self.env.from_string(self.DEFAULT_TEMPLATE)

        return template.render(report=report)

    def generate_pdf(self, report: ForensicReport, filename: str | None = None) -> Path:
        """
        Generate PDF report.

        Args:
            report: ForensicReport data
            filename: Optional filename (without extension)

        Returns:
            Path to generated PDF
        """
        if not WEASYPRINT_AVAILABLE:
            raise RuntimeError(
                "WeasyPrint is not installed. Install with: pip install weasyprint"
            )

        html_content = self.generate_html(report)
        filename = filename or f"report_{report.report_id}"
        pdf_path = self.output_dir / f"{filename}.pdf"

        HTML(string=html_content).write_pdf(pdf_path)
        return pdf_path

    def save_html(self, report: ForensicReport, filename: str | None = None) -> Path:
        """
        Save HTML report to file.

        Args:
            report: ForensicReport data
            filename: Optional filename (without extension)

        Returns:
            Path to saved HTML file
        """
        html_content = self.generate_html(report)
        filename = filename or f"report_{report.report_id}"
        html_path = self.output_dir / f"{filename}.html"

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return html_path


def main():
    """Demo report generation."""
    print("Report Generator Demo\n")

    # Create sample report data
    report = ForensicReport(
        report_id="FR-2024-001",
        title="Security Incident Investigation",
        generated_at=datetime.utcnow(),
        generated_by="Forensic Framework v1.0",
        case_number="CASE-2024-0042",
        incident_start=datetime(2024, 1, 15, 10, 30),
        incident_end=datetime(2024, 1, 15, 14, 45),
        incident_summary=(
            "Unauthorized access detected on production server. "
            "Attacker gained initial access via compromised SSH credentials "
            "and attempted lateral movement to database server."
        ),
        evidence_items=[
            EvidenceItem(
                evidence_id="EV-001",
                description="Auth logs from webserver",
                source="/var/log/auth.log",
                collected_at=datetime(2024, 1, 15, 15, 0),
                hash_value="a1b2c3d4e5f6...",
                merkle_root="f6e5d4c3b2a1...",
            ),
        ],
        timeline=[
            TimelineEvent(
                timestamp=datetime(2024, 1, 15, 10, 30),
                description="First failed SSH login attempt from 203.0.113.50",
                severity="WARNING",
                source="webserver",
            ),
            TimelineEvent(
                timestamp=datetime(2024, 1, 15, 10, 35),
                description="Successful SSH login as admin from 203.0.113.50",
                severity="CRITICAL",
                source="webserver",
            ),
            TimelineEvent(
                timestamp=datetime(2024, 1, 15, 10, 40),
                description="Privilege escalation attempt detected",
                severity="CRITICAL",
                source="webserver",
            ),
        ],
        ai_results=[
            AIAnalysisResult(
                log_id="log-001",
                anomaly_score=0.87,
                is_anomaly=True,
                method="Isolation Forest + Statistical",
                explanation="High anomaly score due to unusual time, rare log template, and rapid succession of events.",
                top_features=[
                    {"name": "hour_of_day", "contribution": 0.35},
                    {"name": "template_rarity", "contribution": 0.28},
                    {"name": "time_since_last", "contribution": 0.19},
                ],
            ),
        ],
        conclusions=[
            "Unauthorized access confirmed via compromised admin credentials",
            "Attacker originated from IP 203.0.113.50 (external)",
            "Lateral movement attempt was detected and blocked",
            "No evidence of data exfiltration found",
        ],
        recommendations=[
            "Rotate all administrative credentials immediately",
            "Implement multi-factor authentication for SSH access",
            "Review and restrict SSH access to VPN-only",
            "Deploy endpoint detection and response (EDR) solution",
        ],
    )

    # Generate reports
    generator = ReportGenerator()

    print("Generating HTML report...")
    html_path = generator.save_html(report)
    print(f"  Saved to: {html_path}")

    if WEASYPRINT_AVAILABLE:
        print("Generating PDF report...")
        pdf_path = generator.generate_pdf(report)
        print(f"  Saved to: {pdf_path}")
    else:
        print("  Skipping PDF (WeasyPrint not installed)")


if __name__ == "__main__":
    main()
