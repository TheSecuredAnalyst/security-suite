"""Security report generator - HTML and PDF reports."""

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from core.logger import get_logger
from core.models import ScanResult, Severity
from modules.ai.correlator import FindingCorrelator


@dataclass
class ReportConfig:
    """Report configuration options."""
    title: str = "Security Assessment Report"
    company_name: str = ""
    assessor_name: str = ""
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_remediation: bool = True
    include_raw_data: bool = False


class ReportGenerator:
    """Generate professional security reports."""

    def __init__(self):
        self.logger = get_logger("ai.reporter")
        self.correlator = FindingCorrelator()

    def generate_html(
        self,
        scan_results: list[ScanResult],
        config: ReportConfig | None = None,
        ai_analysis: str | None = None,
    ) -> str:
        """Generate HTML report.

        Args:
            scan_results: List of scan results
            config: Report configuration
            ai_analysis: Optional AI-generated analysis to include

        Returns:
            HTML report string
        """
        config = config or ReportConfig()
        correlation = self.correlator.correlate(scan_results)

        # Build severity color map
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d",
        }

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{config.title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                line-height: 1.6; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white;
                   padding: 40px; margin-bottom: 30px; border-radius: 10px; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header .meta {{ opacity: 0.8; }}
        .card {{ background: white; border-radius: 10px; padding: 25px; margin-bottom: 20px;
                 box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .card h2 {{ color: #1a1a2e; margin-bottom: 20px; padding-bottom: 10px;
                    border-bottom: 2px solid #eee; }}
        .risk-score {{ display: inline-block; padding: 15px 30px; border-radius: 10px;
                       font-size: 2em; font-weight: bold; color: white; }}
        .risk-critical {{ background: #dc3545; }}
        .risk-high {{ background: #fd7e14; }}
        .risk-medium {{ background: #ffc107; color: #333; }}
        .risk-low {{ background: #17a2b8; }}
        .risk-minimal {{ background: #28a745; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                       gap: 15px; margin: 20px 0; }}
        .stat-box {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-box .number {{ font-size: 2em; font-weight: bold; color: #1a1a2e; }}
        .stat-box .label {{ color: #666; font-size: 0.9em; }}
        .finding {{ border-left: 4px solid; padding: 15px; margin: 10px 0; background: #f8f9fa;
                    border-radius: 0 8px 8px 0; }}
        .finding-critical {{ border-color: #dc3545; }}
        .finding-high {{ border-color: #fd7e14; }}
        .finding-medium {{ border-color: #ffc107; }}
        .finding-low {{ border-color: #17a2b8; }}
        .finding-info {{ border-color: #6c757d; }}
        .finding h3 {{ display: flex; align-items: center; gap: 10px; }}
        .severity-badge {{ padding: 3px 10px; border-radius: 20px; font-size: 0.75em;
                          color: white; text-transform: uppercase; }}
        .badge-critical {{ background: #dc3545; }}
        .badge-high {{ background: #fd7e14; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #17a2b8; }}
        .badge-info {{ background: #6c757d; }}
        .attack-chain {{ background: linear-gradient(90deg, #fff5f5 0%, #f8f9fa 100%);
                         border: 1px solid #ffcccc; padding: 20px; border-radius: 8px; margin: 10px 0; }}
        .attack-chain h3 {{ color: #dc3545; }}
        .recommendation {{ padding: 10px 15px; background: #e8f5e9; border-left: 4px solid #28a745;
                          margin: 10px 0; border-radius: 0 8px 8px 0; }}
        .ai-analysis {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        color: white; padding: 25px; border-radius: 10px; }}
        .ai-analysis h2 {{ color: white; border-bottom-color: rgba(255,255,255,0.3); }}
        .ai-analysis pre {{ background: rgba(0,0,0,0.2); padding: 15px; border-radius: 8px;
                            white-space: pre-wrap; font-family: inherit; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 0.9em; }}
        @media print {{
            body {{ background: white; }}
            .card {{ box-shadow: none; border: 1px solid #ddd; }}
            .header {{ background: #1a1a2e !important; -webkit-print-color-adjust: exact; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{config.title}</h1>
            <div class="meta">
                <p><strong>Target:</strong> {correlation.target}</p>
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                {f'<p><strong>Company:</strong> {config.company_name}</p>' if config.company_name else ''}
                {f'<p><strong>Assessor:</strong> {config.assessor_name}</p>' if config.assessor_name else ''}
            </div>
        </div>
"""

        # Risk Overview Card
        risk_class = f"risk-{correlation.risk_summary.get('risk_level', 'minimal').lower()}"
        html += f"""
        <div class="card">
            <h2>Risk Overview</h2>
            <div style="text-align: center; margin: 20px 0;">
                <div class="risk-score {risk_class}">
                    {correlation.risk_summary.get('overall_score', 0)}/100
                </div>
                <p style="margin-top: 10px; font-size: 1.2em;">
                    Risk Level: <strong>{correlation.risk_summary.get('risk_level', 'Unknown')}</strong>
                </p>
            </div>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="number">{correlation.total_findings}</div>
                    <div class="label">Total Findings</div>
                </div>
                <div class="stat-box">
                    <div class="number">{correlation.unique_findings}</div>
                    <div class="label">Unique Issues</div>
                </div>
                <div class="stat-box">
                    <div class="number">{correlation.risk_summary.get('high_priority_findings', 0)}</div>
                    <div class="label">High Priority</div>
                </div>
                <div class="stat-box">
                    <div class="number">{correlation.risk_summary.get('attack_chains_identified', 0)}</div>
                    <div class="label">Attack Chains</div>
                </div>
            </div>
        </div>
"""

        # Severity Breakdown
        breakdown = correlation.risk_summary.get('severity_breakdown', {})
        html += """
        <div class="card">
            <h2>Severity Breakdown</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                    <th>Distribution</th>
                </tr>
"""
        total = sum(breakdown.values()) or 1
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            count = breakdown.get(sev, 0)
            pct = (count / total) * 100
            color = severity_colors.get(sev, '#666')
            html += f"""
                <tr>
                    <td><span class="severity-badge badge-{sev}">{sev.upper()}</span></td>
                    <td>{count}</td>
                    <td>
                        <div style="background: #eee; border-radius: 4px; overflow: hidden;">
                            <div style="width: {pct}%; background: {color}; height: 20px;"></div>
                        </div>
                    </td>
                </tr>
"""
        html += """
            </table>
        </div>
"""

        # AI Analysis (if provided)
        if ai_analysis and config.include_executive_summary:
            html += f"""
        <div class="card ai-analysis">
            <h2>🤖 AI Security Analysis</h2>
            <pre>{ai_analysis}</pre>
        </div>
"""

        # Attack Chains
        if correlation.attack_chains:
            html += """
        <div class="card">
            <h2>⚠️ Identified Attack Chains</h2>
            <p style="margin-bottom: 15px; color: #666;">
                These represent potential paths an attacker could take to compromise systems.
            </p>
"""
            for chain in correlation.attack_chains:
                html += f"""
            <div class="attack-chain">
                <h3>{chain.name}</h3>
                <p>{chain.description}</p>
                <p><strong>Risk Score:</strong> {chain.risk_score:.1f}/10 |
                   <strong>Findings Involved:</strong> {len(chain.findings)}</p>
            </div>
"""
            html += """
        </div>
"""

        # Recommendations
        if correlation.recommendations and config.include_remediation:
            html += """
        <div class="card">
            <h2>📋 Recommendations</h2>
"""
            for rec in correlation.recommendations:
                html += f"""
            <div class="recommendation">{rec}</div>
"""
            html += """
        </div>
"""

        # Detailed Findings
        if config.include_technical_details:
            html += """
        <div class="card">
            <h2>Detailed Findings</h2>
"""
            # Group by severity
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                sev_findings = [
                    cf for cf in correlation.correlated_findings
                    if cf.finding.severity == severity
                ]
                if sev_findings:
                    html += f"""
            <h3 style="margin-top: 20px; color: {severity_colors.get(severity.value, '#666')};">
                {severity.value.upper()} ({len(sev_findings)})
            </h3>
"""
                    for cf in sev_findings:
                        f = cf.finding
                        html += f"""
            <div class="finding finding-{f.severity.value}">
                <h3>
                    <span class="severity-badge badge-{f.severity.value}">{f.severity.value}</span>
                    {f.title}
                </h3>
                <p style="margin: 10px 0;">{f.description}</p>
                <p style="color: #666; font-size: 0.9em;"><strong>Source:</strong> {f.source}</p>
"""
                        if cf.related_findings:
                            html += f"""
                <p style="color: #666; font-size: 0.9em;">
                    <strong>Related to:</strong> {len(cf.related_findings)} other finding(s)
                </p>
"""
                        if f.references:
                            html += """
                <p style="color: #666; font-size: 0.9em;"><strong>References:</strong></p>
                <ul style="margin-left: 20px; font-size: 0.9em;">
"""
                            for ref in f.references[:3]:
                                html += f'<li><a href="{ref}" target="_blank">{ref}</a></li>'
                            html += "</ul>"

                        html += """
            </div>
"""

            html += """
        </div>
"""

        # Footer
        html += f"""
        <div class="footer">
            <p>Generated by Security Suite • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>This report contains sensitive security information. Handle accordingly.</p>
        </div>
    </div>
</body>
</html>
"""

        return html

    def save_html(
        self,
        scan_results: list[ScanResult],
        output_path: str,
        config: ReportConfig | None = None,
        ai_analysis: str | None = None,
    ) -> Path:
        """Save HTML report to file.

        Args:
            scan_results: List of scan results
            output_path: Output file path
            config: Report configuration
            ai_analysis: Optional AI analysis

        Returns:
            Path to saved file
        """
        html = self.generate_html(scan_results, config, ai_analysis)
        path = Path(output_path)
        path.write_text(html)
        self.logger.info(f"Report saved to {path}")
        return path

    def generate_json(
        self,
        scan_results: list[ScanResult],
        config: ReportConfig | None = None,
    ) -> dict:
        """Generate JSON report.

        Args:
            scan_results: List of scan results
            config: Report configuration

        Returns:
            JSON-serializable report dict
        """
        config = config or ReportConfig()
        correlation = self.correlator.correlate(scan_results)

        return {
            "report_metadata": {
                "title": config.title,
                "generated_at": datetime.now().isoformat(),
                "company": config.company_name,
                "assessor": config.assessor_name,
            },
            "target": correlation.target,
            "risk_summary": correlation.risk_summary,
            "attack_chains": [
                {
                    "name": c.name,
                    "description": c.description,
                    "risk_score": c.risk_score,
                    "mitre_tactics": c.mitre_tactics,
                    "findings": [f.title for f in c.findings],
                }
                for c in correlation.attack_chains
            ],
            "recommendations": correlation.recommendations,
            "findings": [
                {
                    "title": cf.finding.title,
                    "description": cf.finding.description,
                    "severity": cf.finding.severity.value,
                    "source": cf.finding.source,
                    "risk_score": cf.combined_risk_score,
                    "tags": cf.tags,
                    "related_count": len(cf.related_findings),
                    "data": cf.finding.data,
                    "references": cf.finding.references,
                }
                for cf in correlation.correlated_findings
            ],
            "scan_details": [
                {
                    "module": r.module,
                    "target": r.target.value,
                    "success": r.success,
                    "finding_count": len(r.findings),
                    "duration": r.duration_seconds,
                }
                for r in scan_results
            ],
        }

    def save_json(
        self,
        scan_results: list[ScanResult],
        output_path: str,
        config: ReportConfig | None = None,
    ) -> Path:
        """Save JSON report to file."""
        data = self.generate_json(scan_results, config)
        path = Path(output_path)
        path.write_text(json.dumps(data, indent=2, default=str))
        self.logger.info(f"JSON report saved to {path}")
        return path
