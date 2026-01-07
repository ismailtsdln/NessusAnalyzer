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
            if report_node is None:
                raise ValueError("Invalid .nessus file: <Report> tag not found.")
            
            report_name = report_node.get("name", "Unnamed Report")
            report = NessusReport(name=report_name)

            for host_node in report_node.findall("ReportHost"):
                host_name = host_node.get("name", "Unknown Host")
                host = NessusHost(name=host_name)

                # Extract host properties
                host_properties = host_node.find("HostProperties")
                if host_properties is not None:
                    for tag in host_properties.findall("tag"):
                        name = tag.get("name")
                        value = tag.text
                        if not name or not value:
                            continue
                        if name == "host-ip":
                            host.ip = value
                        elif name == "host-fqdn":
                            host.fqdn = value
                        elif name == "operating-system":
                            host.operating_system = value

                # Extract findings
                for item in host_node.findall("ReportItem"):
                    try:
                        severity_str = item.get("severity", "0")
                        severity = int(severity_str) if severity_str.isdigit() else 0
                        
                        finding_data = {
                            "pluginID": item.get("pluginID", "0"),
                            "pluginName": item.get("pluginName", "Unknown Plugin"),
                            "pluginFamily": item.get("pluginFamily", "None"),
                            "severity": severity,
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
                            "cve": [cve.text for cve in item.findall("cve") if cve.text]
                        }

                        cvss_score = item.findtext("cvss_base_score")
                        if cvss_score:
                            try:
                                finding_data["cvssBaseScore"] = float(cvss_score)
                            except ValueError:
                                logger.warning(f"Malformed CVSS score '{cvss_score}' for plugin {finding_data['pluginID']}")

                        finding = NessusFinding(**finding_data)
                        host.findings.append(finding)
                    except Exception as item_err:
                        logger.warning(f"Error parsing ReportItem: {item_err}")
                        continue

                report.hosts.append(host)

            return report

        except Exception as e:
            logger.error(f"Error parsing Nessus file: {e}")
            raise
