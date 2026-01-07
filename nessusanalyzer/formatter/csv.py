import csv
from typing import List
from ..core.models import NessusFinding, NessusReport
from ..utils.logger import logger

class CSVFormatter:
    def __init__(self, report: NessusReport):
        self.report = report

    def export(self, output_path: str):
        """Exports the report to a CSV file."""
        logger.info(f"Exporting report to CSV: {output_path}")
        headers = [
            "Host", "IP", "Plugin ID", "Plugin Name", "Severity", 
            "Risk Factor", "CVSS Base Score", "Exploit Available", "CVE"
        ]

        try:
            with open(output_path, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)

                for host in self.report.hosts:
                    for finding in host.findings:
                        writer.writerow([
                            host.name,
                            host.ip or "",
                            finding.plugin_id,
                            finding.plugin_name,
                            finding.severity,
                            finding.risk_factor,
                            finding.cvss_base_score or "",
                            "Yes" if finding.exploit_available else "No",
                            ", ".join(finding.cve)
                        ])
            logger.info("CSV export completed successfully.")
        except Exception as e:
            logger.error(f"Error during CSV export: {e}")
            raise
