import click
import os
from ..core.parser import NessusParser
from ..analyzer.engine import AnalyzerEngine
from ..formatter.csv import CSVFormatter
from ..formatter.json import JSONFormatter
from ..formatter.excel import ExcelFormatter
from ..formatter.pdf import PDFFormatter
from ..utils.logger import logger, setup_logger

@click.group()
@click.option('--debug', is_flag=True, help="Enable debug logging")
def cli(debug):
    """NessusAnalyzer: A modern vulnerability output parser and reporting toolkit."""
    if debug:
        setup_logger(level=10) # DEBUG level

@cli.command()
@click.argument('file', type=click.Path(exists=True))
@click.option('--summary', is_flag=True, help="Show a brief summary of findings")
def parse(file, summary):
    """Parses a .nessus file and displays findings."""
    parser = NessusParser(file)
    report = parser.parse()
    
    if summary:
        analyzer = AnalyzerEngine(report)
        risk_summary = analyzer.get_risk_summary()
        click.echo(f"\nReport Summary for: {report.name}")
        click.echo("-" * 40)
        for severity, count in risk_summary.items():
            click.echo(f"{severity:10}: {count}")
        
        exploitable = analyzer.get_exploitable_vulnerabilities()
        click.echo(f"Exploitable findings: {len(exploitable)}")
    else:
        click.echo(f"Successfully parsed {file}. Use --summary to see details.")

@cli.command()
@click.argument('file', type=click.Path(exists=True))
@click.option('--format', type=click.Choice(['csv', 'json', 'xlsx', 'pdf']), default='json', help="Output format")
@click.option('--output', '-o', type=click.Path(), help="Output file path")
def export(file, format, output):
    """Parses a .nessus file and exports it to the specified format."""
    parser = NessusParser(file)
    report = parser.parse()
    
    if not output:
        output = f"output.{format}"

    if format == 'csv':
        formatter = CSVFormatter(report)
    elif format == 'json':
        formatter = JSONFormatter(report)
    elif format == 'xlsx':
        formatter = ExcelFormatter(report)
    elif format == 'pdf':
        formatter = PDFFormatter(report)
    
    formatter.export(output)
    click.echo(f"Report exported to {output}")

@cli.command()
@click.argument('file', type=click.Path(exists=True))
def exploitable(file):
    """Lists all exploitable vulnerabilities found in the scan."""
    parser = NessusParser(file)
    report = parser.parse()
    analyzer = AnalyzerEngine(report)
    exploitable_findings = analyzer.get_exploitable_vulnerabilities()
    
    if not exploitable_findings:
        click.echo("No exploitable vulnerabilities found.")
        return

    click.echo(f"\nFound {len(exploitable_findings)} exploitable vulnerabilities:")
    click.echo("-" * 60)
    for finding in exploitable_findings:
        click.echo(f"- {finding.plugin_name} (Plugin ID: {finding.plugin_id})")

def main():
    cli()

if __name__ == "__main__":
    main()
