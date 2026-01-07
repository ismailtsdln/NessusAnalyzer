from typing import List, Optional, Dict
from pydantic import BaseModel, Field

class NessusFinding(BaseModel):
    plugin_id: str = Field(..., alias="pluginID")
    plugin_name: str = Field(..., alias="pluginName")
    plugin_family: str = Field(..., alias="pluginFamily")
    severity: int
    risk_factor: str = Field(..., alias="riskFactor")
    description: str
    solution: Optional[str] = None
    synopsis: Optional[str] = None
    cve: List[str] = []
    cvss_base_score: Optional[float] = Field(None, alias="cvssBaseScore")
    cvss_vector: Optional[str] = Field(None, alias="cvssVector")
    exploit_available: bool = Field(False, alias="exploitAvailable")
    exploit_code_maturity: Optional[str] = Field(None, alias="exploitCodeMaturity")
    metasploit_name: Optional[str] = Field(None, alias="metasploitName")
    plugin_output: Optional[str] = Field(None, alias="pluginOutput")

class NessusHost(BaseModel):
    name: str
    ip: Optional[str] = None
    fqdn: Optional[str] = None
    operating_system: Optional[str] = Field(None, alias="os")
    findings: List[NessusFinding] = []

class NessusReport(BaseModel):
    name: str
    hosts: List[NessusHost] = []
    policy_name: Optional[str] = None
    scan_start: Optional[str] = None
    scan_end: Optional[str] = None
