"""Export utilities for scan results in multiple formats."""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Optional
from io import StringIO

from core.models import ScanResult
from core.logger import get_logger

logger = get_logger("core.exporters")


class BaseExporter:
    """Base class for result exporters."""
    
    def __init__(self, result: ScanResult):
        """Initialize exporter.
        
        Args:
            result: ScanResult to export
        """
        self.result = result
    
    def export(self, output_path: Optional[Path] = None) -> str:
        """Export result.
        
        Args:
            output_path: Path to save result, or None to return string
            
        Returns:
            Exported content as string
        """
        raise NotImplementedError


class JSONExporter(BaseExporter):
    """Export scan results as JSON."""
    
    def export(self, output_path: Optional[Path] = None) -> str:
        """Export as JSON.
        
        Args:
            output_path: Path to save JSON file
            
        Returns:
            JSON string
        """
        data = {
            "target": self.result.target.dict(),
            "module": self.result.module,
            "success": self.result.success,
            "started_at": self.result.started_at.isoformat() if self.result.started_at else None,
            "completed_at": self.result.completed_at.isoformat() if self.result.completed_at else None,
            "findings": [
                {
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "source": f.source,
                    "data": f.data,
                    "timestamp": f.timestamp.isoformat(),
                }
                for f in self.result.findings
            ],
            "findings_count": len(self.result.findings),
        }
        
        json_str = json.dumps(data, indent=2)
        
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(json_str)
            logger.info(f"Exported JSON to {output_path}")
        
        return json_str


class CSVExporter(BaseExporter):
    """Export scan results as CSV."""
    
    def export(self, output_path: Optional[Path] = None) -> str:
        """Export as CSV.
        
        Args:
            output_path: Path to save CSV file
            
        Returns:
            CSV string
        """
        output = StringIO()
        
        fieldnames = ['Title', 'Severity', 'Source', 'Description', 'Data', 'Timestamp']
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for finding in self.result.findings:
            writer.writerow({
                'Title': finding.title,
                'Severity': finding.severity.value,
                'Source': finding.source,
                'Description': finding.description,
                'Data': json.dumps(finding.data),
                'Timestamp': finding.timestamp.isoformat(),
            })
        
        csv_str = output.getvalue()
        
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', newline='') as f:
                f.write(csv_str)
            logger.info(f"Exported CSV to {output_path}")
        
        return csv_str


class HTMLExporter(BaseExporter):
    """Export scan results as HTML report."""
    
    def export(self, output_path: Optional[Path] = None) -> str:
        """Export as HTML.
        
        Args:
            output_path: Path to save HTML file
            
        Returns:
            HTML string
        """
        severity_colors = {
            "critical": "#ff0000",
            "high": "#ff6600",
            "medium": "#ffaa00",
            "low": "#ffff00",
            "info": "#00aa00",
        }
        
        findings_html = ""
        for finding in self.result.findings:
            color = severity_colors.get(finding.severity.value, "#999999")
            findings_html += f"""
        <tr>
            <td style="border: 1px solid #ddd; padding: 8px;">
                <span style="background-color: {color}; color: white; padding: 2px 8px; border-radius: 3px;">
                    {finding.severity.value.upper()}
                </span>
            </td>
            <td style="border: 1px solid #ddd; padding: 8px;"><strong>{finding.title}</strong></td>
            <td style="border: 1px solid #ddd; padding: 8px;">{finding.source}</td>
            <td style="border: 1px solid #ddd; padding: 8px;">{finding.description}</td>
        </tr>"""
        
        if not findings_html:
            findings_html = "<tr><td colspan='4' style='text-align: center; padding: 20px;'>No findings detected</td></tr>"
        
        critical_count = sum(1 for f in self.result.findings if f.severity.value == 'critical')
        high_count = sum(1 for f in self.result.findings if f.severity.value == 'high')
        medium_count = sum(1 for f in self.result.findings if f.severity.value == 'medium')
        low_count = sum(1 for f in self.result.findings if f.severity.value == 'low')
        info_count = sum(1 for f in self.result.findings if f.severity.value == 'info')
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Suite Scan Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 10px;
            margin: 20px 0;
        }}
        .summary-card {{
            text-align: center;
            padding: 15px;
            border-radius: 5px;
            color: white;
        }}
        .critical {{ background-color: #ff0000; }}
        .high {{ background-color: #ff6600; }}
        .medium {{ background-color: #ffaa00; color: #000; }}
        .low {{ background-color: #ffff00; color: #000; }}
        .info {{ background-color: #00aa00; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th {{
            background-color: #007bff;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 12px;
            border: 1px solid #ddd;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Suite Scan Report</h1>
        <p><strong>Target:</strong> {self.result.target.value} | <strong>Module:</strong> {self.result.module}</p>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-card critical"><strong>{critical_count}</strong><br>Critical</div>
            <div class="summary-card high"><strong>{high_count}</strong><br>High</div>
            <div class="summary-card medium"><strong>{medium_count}</strong><br>Medium</div>
            <div class="summary-card low"><strong>{low_count}</strong><br>Low</div>
            <div class="summary-card info"><strong>{info_count}</strong><br>Info</div>
        </div>
        
        <h2>Findings</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Source</th>
                <th>Description</th>
            </tr>
            {findings_html}
        </table>
    </div>
</body>
</html>"""
        
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(html)
            logger.info(f"Exported HTML to {output_path}")
        
        return html


class MarkdownExporter(BaseExporter):
    """Export scan results as Markdown."""
    
    def export(self, output_path: Optional[Path] = None) -> str:
        """Export as Markdown.
        
        Args:
            output_path: Path to save Markdown file
            
        Returns:
            Markdown string
        """
        md = f"""# Security Suite Scan Report

## Target Information
- **Target:** {self.result.target.value}
- **Module:** {self.result.module}
- **Started:** {self.result.started_at.isoformat() if self.result.started_at else 'N/A'}
- **Completed:** {self.result.completed_at.isoformat() if self.result.completed_at else 'N/A'}

## Summary
- **Total Findings:** {len(self.result.findings)}
- **Critical:** {sum(1 for f in self.result.findings if f.severity.value == 'critical')}
- **High:** {sum(1 for f in self.result.findings if f.severity.value == 'high')}
- **Medium:** {sum(1 for f in self.result.findings if f.severity.value == 'medium')}
- **Low:** {sum(1 for f in self.result.findings if f.severity.value == 'low')}
- **Info:** {sum(1 for f in self.result.findings if f.severity.value == 'info')}

## Findings

"""
        
        if not self.result.findings:
            md += "✅ No findings detected\n"
        else:
            for finding in self.result.findings:
                md += f"""### {finding.title}
- **Severity:** {finding.severity.value.upper()}
- **Source:** {finding.source}
- **Description:** {finding.description}

"""
        
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(md)
            logger.info(f"Exported Markdown to {output_path}")
        
        return md


def export_result(
    result: ScanResult,
    format: str = "json",
    output_path: Optional[Path] = None,
) -> str:
    """Export scan result in specified format.
    
    Args:
        result: ScanResult to export
        format: Export format (json, csv, html, markdown)
        output_path: Path to save file
        
    Returns:
        Exported content as string
    """
    exporters = {
        "json": JSONExporter,
        "csv": CSVExporter,
        "html": HTMLExporter,
        "markdown": MarkdownExporter,
        "md": MarkdownExporter,
    }
    
    if format not in exporters:
        raise ValueError(f"Unknown export format: {format}. Available: {list(exporters.keys())}")
    
    exporter = exporters[format](result)
    return exporter.export(output_path)
