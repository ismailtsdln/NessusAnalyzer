import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from ..core.parser import NessusParser
from ..analyzer.engine import AnalyzerEngine
from ..formatter.csv import CSVFormatter
from ..formatter.json import JSONFormatter
from ..formatter.excel import ExcelFormatter
from ..formatter.pdf import PDFFormatter
from ..utils.logger import logger, setup_logger

console = Console()

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
    if not file.endswith('.nessus'):
        console.print("[bold red]Error:[/bold red] Input file must have a .nessus extension.")
        return

    with Progress(transient=True) as progress:
        progress.add_task("[cyan]Parsing Nessus file...", total=None)
        parser = NessusParser(file)
        report = parser.parse()
    
    if summary:
        analyzer = AnalyzerEngine(report)
        risk_summary = analyzer.get_risk_summary()
        
        table = Table(title=f"Report Summary: [bold blue]{report.name}[/bold blue]", show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="dim")
        table.add_column("Count", justify="right")
        
        severity_styles = {
            "Critical": "bold red",
            "High": "bold orange3",
            "Medium": "bold yellow",
            "Low": "bold green",
            "Info": "bold blue"
        }
        
        for severity, count in risk_summary.items():
            table.add_row(severity, str(count), style=severity_styles.get(severity, "white"))
        
        console.print(table)
        
        exploitable = analyzer.get_exploitable_vulnerabilities()
        console.print(Panel(f"Exploitable findings: [bold red]{len(exploitable)}[/bold red]", expand=False))
    else:
        console.print(f"[green]Successfully parsed[/green] {file}. Use [bold]--summary[/bold] to see details.")

@cli.command()
@click.argument('file', type=click.Path(exists=True))
@click.option('--format', type=click.Choice(['csv', 'json', 'xlsx', 'pdf']), default='json', help="Output format")
@click.option('--output', '-o', type=click.Path(), help="Output file path")
def export(file, format, output):
    """Parses a .nessus file and exports it to the specified format."""
    with Progress(transient=True) as progress:
        progress.add_task(f"[cyan]Exporting to {format}...", total=None)
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
    
    console.print(f"[bold green]✓[/bold green] Report exported to [bold blue]{output}[/bold blue]")

@cli.command()
@click.argument('file', type=click.Path(exists=True))
def exploitable(file):
    """Lists all exploitable vulnerabilities found in the scan."""
    parser = NessusParser(file)
    report = parser.parse()
    analyzer = AnalyzerEngine(report)
    exploitable_findings = analyzer.get_exploitable_vulnerabilities()
    
    if not exploitable_findings:
        console.print("[yellow]No exploitable vulnerabilities found.[/yellow]")
        return

    table = Table(title=f"Found [bold red]{len(exploitable_findings)}[/bold red] exploitable vulnerabilities", show_header=True, header_style="bold red")
    table.add_column("Plugin ID", style="dim")
    table.add_column("Vulnerability Name")

    for finding in exploitable_findings:
        table.add_row(finding.plugin_id, finding.plugin_name)
    
    console.print(table)

def main():
    cli()

if __name__ == "__main__":
    main()
