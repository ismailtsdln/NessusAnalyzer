from typing import List, Dict, Any
from ..core.models import NessusReport, NessusHost, NessusFinding
from ..utils.logger import logger

class AnalyzerEngine:
    def __init__(self, report: NessusReport):
        self.report = report

    def get_exploitable_vulnerabilities(self) -> List[NessusFinding]:
        """Returns a list of all vulnerabilities with available exploits."""
        exploitable = []
        for host in self.report.hosts:
            for finding in host.findings:
                if finding.exploit_available:
                    exploitable.append(finding)
        return exploitable

    def get_vulnerabilities_by_severity(self, min_severity: int = 3) -> List[NessusFinding]:
        """Returns findings with severity equal to or greater than min_severity."""
        filtered = []
        for host in self.report.hosts:
            for finding in host.findings:
                if finding.severity >= min_severity:
                    filtered.append(finding)
        return filtered

    def group_by_host(self) -> Dict[str, List[NessusFinding]]:
        """Groups findings by host name."""
        grouped = {}
        for host in self.report.hosts:
            grouped[host.name] = host.findings
        return grouped

    def get_risk_summary(self) -> Dict[str, int]:
        """Returns a summary of findings count by severity."""
        summary = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        severity_map = {
            4: "Critical",
            3: "High",
            2: "Medium",
            1: "Low",
            0: "Info"
        }
        for host in self.report.hosts:
            for finding in host.findings:
                label = severity_map.get(finding.severity, "Info")
                summary[label] += 1
        return summary

    def get_metasploit_modules(self) -> List[str]:
        """Returns a unique list of Metasploit module names found in the report."""
        modules = set()
        for host in self.report.hosts:
            for finding in host.findings:
                if finding.metasploit_name:
                    modules.add(finding.metasploit_name)
        return list(modules)
