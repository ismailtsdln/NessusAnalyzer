from fpdf import FPDF
from ..core.models import NessusReport
from ..utils.logger import logger

class PDFFormatter(FPDF):
    def __init__(self, report: NessusReport):
        super().__init__()
        self.report = report
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        self.set_font('helvetica', 'B', 15)
        self.cell(0, 10, f'Nessus Security Report: {self.report.name}', border=0, align='C', new_x="LMARGIN", new_y="NEXT")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', border=0, align='C')

    def export(self, output_path: str):
        """Exports the report to a PDF file."""
        logger.info(f"Exporting full report to PDF: {output_path}")
        self.add_page()
        
        # Summary Section
        self.set_font('helvetica', 'B', 12)
        self.cell(0, 10, 'Executive Summary', new_x="LMARGIN", new_y="NEXT", align='L')
        self.set_font('helvetica', '', 10)
        self.cell(0, 7, f'Total Hosts: {len(self.report.hosts)}', new_x="LMARGIN", new_y="NEXT", align='L')
        
        finding_count = sum(len(h.findings) for h in self.report.hosts)
        self.cell(0, 7, f'Total Findings: {finding_count}', new_x="LMARGIN", new_y="NEXT", align='L')
        self.ln(5)

        # Host and Findings Section
        for host in self.report.hosts:
            self.set_font('helvetica', 'B', 11)
            self.set_fill_color(220, 230, 241)
            self.cell(190, 10, f'Host: {host.name} ({host.ip or "N/A"})', border=1, new_x="LMARGIN", new_y="NEXT", align='L', fill=True)
            self.ln(2)

            for finding in host.findings:
                # Severity Color coding
                if finding.severity == 4: # Critical
                    self.set_text_color(255, 0, 0)
                elif finding.severity == 3: # High
                    self.set_text_color(255, 128, 0)
                else:
                    self.set_text_color(0, 0, 0)

                self.set_font('helvetica', 'B', 10)
                self.multi_cell(190, 7, f'[{finding.risk_factor}] {finding.plugin_name}')
                self.set_text_color(0, 0, 0)
                
                self.set_font('helvetica', '', 9)
                desc = finding.description if finding.description else "No description available"
                self.multi_cell(190, 5, f'Description: {desc[:2000]}...')
                
                if finding.solution:
                    self.multi_cell(190, 5, f'Solution: {finding.solution[:2000]}')
                
                self.ln(3)

        try:
            self.output(output_path)
            logger.info("Full PDF report generated successfully.")
        except Exception as e:
            logger.error(f"Error during PDF export: {e}")
            raise
