import pytest
import os
from nessusanalyzer.core.parser import NessusParser
from nessusanalyzer.analyzer.engine import AnalyzerEngine

def test_parser_basic():
    sample_file = os.path.join(os.path.dirname(__file__), "sample.nessus")
    parser = NessusParser(sample_file)
    report = parser.parse()
    
    assert report.name == "Sample Scan"
    assert len(report.hosts) == 1
    assert report.hosts[0].name == "192.168.1.10"
    assert len(report.hosts[0].findings) == 2

def test_analyzer_exploitable():
    sample_file = os.path.join(os.path.dirname(__file__), "sample.nessus")
    parser = NessusParser(sample_file)
    report = parser.parse()
    analyzer = AnalyzerEngine(report)
    
    exploitable = analyzer.get_exploitable_vulnerabilities()
    assert len(exploitable) == 1
    assert exploitable[0].plugin_id == "12345"
    assert exploitable[0].exploit_available is True

def test_analyzer_summary():
    sample_file = os.path.join(os.path.dirname(__file__), "sample.nessus")
    parser = NessusParser(sample_file)
    report = parser.parse()
    analyzer = AnalyzerEngine(report)
    
    summary = analyzer.get_risk_summary()
    assert summary["High"] == 1
    assert summary["Low"] == 1
    assert summary["Critical"] == 0

def test_formatters(tmp_path):
    from nessusanalyzer.formatter.csv import CSVFormatter
    from nessusanalyzer.formatter.json import JSONFormatter
    from nessusanalyzer.formatter.excel import ExcelFormatter
    from nessusanalyzer.formatter.pdf import PDFFormatter

    sample_file = os.path.join(os.path.dirname(__file__), "sample.nessus")
    parser = NessusParser(sample_file)
    report = parser.parse()

    # CSV
    csv_file = tmp_path / "output.csv"
    CSVFormatter(report).export(str(csv_file))
    assert csv_file.exists()

    # JSON
    json_file = tmp_path / "output.json"
    JSONFormatter(report).export(str(json_file))
    assert json_file.exists()

    # XLSX
    xlsx_file = tmp_path / "output.xlsx"
    ExcelFormatter(report).export(str(xlsx_file))
    assert xlsx_file.exists()

    # PDF
    pdf_file = tmp_path / "output.pdf"
    PDFFormatter(report).export(str(pdf_file))
    assert pdf_file.exists()
