"""Tests for export functionality."""

import pytest
import json
import csv
from io import StringIO
from pathlib import Path

from core.exporters import (
    JSONExporter, CSVExporter, HTMLExporter, MarkdownExporter,
    export_result
)
from core.models import Target, ScanResult, Finding, Severity


@pytest.fixture
def sample_result():
    """Create sample ScanResult for testing."""
    target = Target.from_string("example.com")
    result = ScanResult(target=target, module="test_module")
    
    for i, severity in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]):
        finding = Finding(
            title=f"Test Finding {i}",
            description=f"Description {i}",
            severity=severity,
            source="test",
            data={"test_key": f"test_value_{i}"},
        )
        result.findings.append(finding)
    
    return result


class TestJSONExporter:
    """Tests for JSONExporter."""
    
    def test_export_json_to_string(self, sample_result):
        """Test exporting to JSON string."""
        exporter = JSONExporter(sample_result)
        json_str = exporter.export()
        
        data = json.loads(json_str)
        assert data["target"]["value"] == "example.com"
        assert data["module"] == "test_module"
        assert data["findings_count"] == 3
        assert len(data["findings"]) == 3
    
    def test_export_json_to_file(self, sample_result, tmp_path):
        """Test exporting to JSON file."""
        exporter = JSONExporter(sample_result)
        output_file = tmp_path / "result.json"
        
        exporter.export(output_file)
        
        assert output_file.exists()
        with open(output_file, 'r') as f:
            data = json.load(f)
            assert data["target"]["value"] == "example.com"
            assert data["findings_count"] == 3


class TestCSVExporter:
    """Tests for CSVExporter."""
    
    def test_export_csv_to_string(self, sample_result):
        """Test exporting to CSV string."""
        exporter = CSVExporter(sample_result)
        csv_str = exporter.export()
        
        reader = csv.DictReader(StringIO(csv_str))
        rows = list(reader)
        
        assert len(rows) == 3
        # Finding columns may vary, just check basic structure
        assert "Title" in rows[0]
        assert rows[0]["Title"] == "Test Finding 0"
    
    def test_export_csv_to_file(self, sample_result, tmp_path):
        """Test exporting to CSV file."""
        exporter = CSVExporter(sample_result)
        output_file = tmp_path / "result.csv"
        
        exporter.export(output_file)
        
        assert output_file.exists()
        with open(output_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 3


class TestHTMLExporter:
    """Tests for HTMLExporter."""
    
    def test_export_html_to_string(self, sample_result):
        """Test exporting to HTML string."""
        exporter = HTMLExporter(sample_result)
        html_str = exporter.export()
        
        assert "<!DOCTYPE html>" in html_str
        assert "Security Suite Scan Report" in html_str
        assert "Test Finding 0" in html_str
        assert sample_result.target.value in html_str
    
    def test_export_html_to_file(self, sample_result, tmp_path):
        """Test exporting to HTML file."""
        exporter = HTMLExporter(sample_result)
        output_file = tmp_path / "result.html"
        
        exporter.export(output_file)
        
        assert output_file.exists()
        content = output_file.read_text()
        assert "<!DOCTYPE html>" in content


class TestMarkdownExporter:
    """Tests for MarkdownExporter."""
    
    def test_export_markdown_to_string(self, sample_result):
        """Test exporting to Markdown string."""
        exporter = MarkdownExporter(sample_result)
        md_str = exporter.export()
        
        assert "# Security Suite Scan Report" in md_str
        assert "Test Finding 0" in md_str
        assert sample_result.target.value in md_str
        assert "Critical:" in md_str
    
    def test_export_markdown_to_file(self, sample_result, tmp_path):
        """Test exporting to Markdown file."""
        exporter = MarkdownExporter(sample_result)
        output_file = tmp_path / "result.md"
        
        exporter.export(output_file)
        
        assert output_file.exists()
        content = output_file.read_text()
        assert "# Security Suite Scan Report" in content


class TestExportFunction:
    """Tests for export_result function."""
    
    def test_export_json(self, sample_result):
        """Test exporting as JSON."""
        result = export_result(sample_result, format="json")
        data = json.loads(result)
        assert data["target"]["value"] == "example.com"
    
    def test_export_csv(self, sample_result):
        """Test exporting as CSV."""
        result = export_result(sample_result, format="csv")
        reader = csv.DictReader(StringIO(result))
        rows = list(reader)
        assert len(rows) == 3
    
    def test_export_html(self, sample_result):
        """Test exporting as HTML."""
        result = export_result(sample_result, format="html")
        assert "<!DOCTYPE html>" in result
    
    def test_export_markdown(self, sample_result):
        """Test exporting as Markdown."""
        result = export_result(sample_result, format="markdown")
        assert "# Security Suite Scan Report" in result
    
    def test_export_markdown_shorthand(self, sample_result):
        """Test exporting as Markdown with 'md' shorthand."""
        result = export_result(sample_result, format="md")
        assert "# Security Suite Scan Report" in result
    
    def test_export_invalid_format(self, sample_result):
        """Test exporting with invalid format raises error."""
        with pytest.raises(ValueError):
            export_result(sample_result, format="invalid")


class TestExportEmpty:
    """Tests for exporting empty results."""
    
    def test_export_no_findings(self):
        """Test exporting result with no findings."""
        target = Target.from_string("example.com")
        result = ScanResult(target=target, module="test")
        
        html = export_result(result, format="html")
        assert "No findings detected" in html
        
        md = export_result(result, format="markdown")
        assert "No findings detected" in md
