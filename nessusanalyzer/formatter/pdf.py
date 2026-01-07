from fpdf import FPDF
from ..core.models import NessusReport
from ..utils.logger import logger

class PDFFormatter(FPDF):
    def __init__(self, report: NessusReport):
        super().__init__()
        self.report = report

    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, f'Nessus Security Report: {self.report.name}', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def export(self, output_path: str):
        """Exports the report to a PDF file."""
        logger.info(f"Exporting report to PDF: {output_path}")
        self.add_page()
        
        # Summary Section
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Executive Summary', 0, 1, 'L')
        self.set_font('Arial', '', 10)
        self.cell(0, 7, f'Total Hosts: {len(self.report.hosts)}', 0, 1, 'L')
        
        finding_count = sum(len(h.findings) for h in self.report.hosts)
        self.cell(0, 7, f'Total Findings: {finding_count}', 0, 1, 'L')
        self.ln(10)

        # Host and Findings Section
        for host in self.report.hosts:
            self.set_font('Arial', 'B', 11)
            self.set_fill_color(200, 220, 255)
            self.cell(0, 10, f'Host: {host.name} ({host.ip or "N/A"})', 1, 1, 'L', 1)
            self.ln(2)

            for finding in host.findings:
                # Severity Color coding
                if finding.severity == 4: # Critical
                    self.set_text_color(255, 0, 0)
                elif finding.severity == 3: # High
                    self.set_text_color(255, 102, 0)
                else:
                    self.set_text_color(0, 0, 0)

                self.set_font('Arial', 'B', 10)
                self.multi_cell(0, 7, f'[{finding.risk_factor}] {finding.plugin_name}')
                self.set_text_color(0, 0, 0)
                
                self.set_font('Arial', '', 9)
                self.multi_cell(0, 5, f'Description: {finding.description[:500]}...')
                if finding.solution:
                    self.multi_cell(0, 5, f'Solution: {finding.solution[:500]}...')
                
                self.ln(5)

            if self.get_y() > 250:
                self.add_page()

        try:
            self.output(output_path)
            logger.info("PDF export completed successfully.")
        except Exception as e:
            logger.error(f"Error during PDF export: {e}")
            raise
