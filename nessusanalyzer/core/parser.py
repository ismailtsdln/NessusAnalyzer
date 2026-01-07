from lxml import etree
from typing import List, Optional
from .models import NessusReport, NessusHost, NessusFinding
from ..utils.logger import logger

class NessusParser:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.tree = None

    def parse(self) -> NessusReport:
        """Parses the .nessus XML file and returns a NessusReport object."""
        try:
            logger.info(f"Parsing Nessus file: {self.file_path}")
            self.tree = etree.parse(self.file_path)
            root = self.tree.getroot()

            report_node = root.find("Report")
            report_name = report_node.get("name")
            
            report = NessusReport(name=report_name)

            for host_node in report_node.findall("ReportHost"):
                host_name = host_node.get("name")
                host = NessusHost(name=host_name)

                # Extract host properties
                host_properties = host_node.find("HostProperties")
                if host_properties is not None:
                    for tag in host_properties.findall("tag"):
                        name = tag.get("name")
                        value = tag.text
                        if name == "host-ip":
                            host.ip = value
                        elif name == "host-fqdn":
                            host.fqdn = value
                        elif name == "operating-system":
                            host.operating_system = value

                # Extract findings
                for item in host_node.findall("ReportItem"):
                    finding_data = {
                        "pluginID": item.get("pluginID"),
                        "pluginName": item.get("pluginName"),
                        "pluginFamily": item.get("pluginFamily"),
                        "severity": int(item.get("severity")),
                        "riskFactor": item.findtext("risk_factor", "None"),
                        "description": item.findtext("description", ""),
                        "solution": item.findtext("solution"),
                        "synopsis": item.findtext("synopsis"),
                        "exploitAvailable": item.findtext("exploit_available") == "true",
                        "exploitCodeMaturity": item.findtext("exploit_code_maturity"),
                        "metasploitName": item.findtext("metasploit_name"),
                        "pluginOutput": item.findtext("plugin_output"),
                        "cvssBaseScore": None,
                        "cvssVector": item.findtext("cvss_vector"),
                        "cve": [cve.text for cve in item.findall("cve")]
                    }

                    cvss_score = item.findtext("cvss_base_score")
                    if cvss_score:
                        finding_data["cvssBaseScore"] = float(cvss_score)

                    finding = NessusFinding(**finding_data)
                    host.findings.append(finding)

                report.hosts.append(host)

            return report

        except Exception as e:
            logger.error(f"Error parsing Nessus file: {e}")
            raise
