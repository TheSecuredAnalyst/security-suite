"""
MITRE ATT&CK mapper — tags every finding with a technique ID, tactic, and name.

Data source: MITRE ATT&CK Enterprise matrix (manually curated subset).
Covers: CVE IDs, service/port-based findings, and misconfiguration patterns.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ATTACKTag:
    technique_id: str    # e.g. "T1190"
    sub_technique: str   # e.g. "" or ".001"
    tactic: str          # e.g. "Initial Access"
    tactic_id: str       # e.g. "TA0001"
    name: str            # e.g. "Exploit Public-Facing Application"
    description: str = ""
    mitigations: list[str] = None  # M-IDs

    def __post_init__(self):
        if self.mitigations is None:
            self.mitigations = []

    @property
    def full_id(self) -> str:
        return f"{self.technique_id}{self.sub_technique}"

    def to_dict(self) -> dict:
        return {
            "technique_id": self.full_id,
            "tactic": self.tactic,
            "tactic_id": self.tactic_id,
            "name": self.name,
            "description": self.description,
            "url": f"https://attack.mitre.org/techniques/{self.technique_id.replace('.', '/')}",
        }


# ── Tactic reference ──────────────────────────────────────────────────────────

TACTICS = {
    "Initial Access":        "TA0001",
    "Execution":             "TA0002",
    "Persistence":           "TA0003",
    "Privilege Escalation":  "TA0004",
    "Defense Evasion":       "TA0005",
    "Credential Access":     "TA0006",
    "Discovery":             "TA0007",
    "Lateral Movement":      "TA0008",
    "Collection":            "TA0009",
    "Command and Control":   "TA0011",
    "Exfiltration":          "TA0010",
    "Impact":                "TA0040",
}


def _t(technique_id: str, tactic: str, name: str, description: str = "", sub: str = "") -> ATTACKTag:
    return ATTACKTag(
        technique_id=technique_id,
        sub_technique=sub,
        tactic=tactic,
        tactic_id=TACTICS.get(tactic, ""),
        name=name,
        description=description,
    )


# ── CVE → ATT&CK mapping ─────────────────────────────────────────────────────

CVE_MAP: dict[str, ATTACKTag] = {

    # EternalBlue family
    "CVE-2017-0144": _t("T1210", "Lateral Movement", "Exploitation of Remote Services",
                         "EternalBlue SMB RCE — used in WannaCry and NotPetya"),
    "CVE-2017-0145": _t("T1210", "Lateral Movement", "Exploitation of Remote Services",
                         "EternalRomance SMB RCE"),
    "CVE-2017-0147": _t("T1210", "Lateral Movement", "Exploitation of Remote Services",
                         "EternalChampion SMB RCE"),
    "CVE-2020-0796": _t("T1210", "Lateral Movement", "Exploitation of Remote Services",
                         "SMBGhost — SMBv3 compression buffer overflow"),

    # RDP
    "CVE-2019-0708": _t("T1210", "Lateral Movement", "Exploitation of Remote Services",
                         "BlueKeep — unauthenticated RDP RCE"),
    "CVE-2019-1182": _t("T1210", "Lateral Movement", "Exploitation of Remote Services",
                         "DejaBlue — RDP RCE"),

    # PrintNightmare
    "CVE-2021-34527": _t("T1068", "Privilege Escalation", "Exploitation for Privilege Escalation",
                          "PrintNightmare — Windows Print Spooler LPE/RCE"),
    "CVE-2021-1675":  _t("T1068", "Privilege Escalation", "Exploitation for Privilege Escalation",
                          "PrintNightmare (original patch bypass)"),

    # Active Directory
    "CVE-2020-1472": _t("T1557", "Credential Access", "Adversary-in-the-Middle",
                         "Zerologon — Netlogon privilege escalation to domain admin", sub=".001"),
    "CVE-2021-42278": _t("T1558", "Credential Access", "Steal or Forge Kerberos Tickets",
                          "noPac — sAMAccountName spoofing to domain admin", sub=".003"),

    # Exchange
    "CVE-2021-26855": _t("T1190", "Initial Access", "Exploit Public-Facing Application",
                          "ProxyLogon — Exchange SSRF + deserialization RCE"),
    "CVE-2021-31207": _t("T1190", "Initial Access", "Exploit Public-Facing Application",
                          "ProxyShell — Exchange pre-auth RCE chain"),

    # Log4Shell
    "CVE-2021-44228": _t("T1190", "Initial Access", "Exploit Public-Facing Application",
                          "Log4Shell — Log4j2 JNDI lookup RCE (critical/widespread)"),
    "CVE-2021-45046": _t("T1190", "Initial Access", "Exploit Public-Facing Application",
                          "Log4Shell variant — incomplete fix bypass"),

    # Confluence
    "CVE-2022-26134": _t("T1190", "Initial Access", "Exploit Public-Facing Application",
                          "Confluence OGNL injection — pre-auth RCE"),
    "CVE-2023-22515": _t("T1190", "Initial Access", "Exploit Public-Facing Application",
                          "Confluence broken access control — create admin account"),

    # Apache
    "CVE-2021-41773": _t("T1190", "Initial Access", "Exploit Public-Facing Application",
                          "Apache httpd 2.4.49 path traversal and RCE"),
    "CVE-2021-42013": _t("T1190", "Initial Access", "Exploit Public-Facing Application",
                          "Apache httpd 2.4.50 path traversal (patch bypass)"),
    "CVE-2017-5638":  _t("T1190", "Initial Access", "Exploit Public-Facing Application",
                          "Apache Struts2 Content-Type OGNL injection"),
    "CVE-2014-6271":  _t("T1190", "Initial Access", "Exploit Public-Facing Application",
                          "Shellshock — bash env variable RCE via CGI"),

    # ActiveMQ
    "CVE-2023-46604": _t("T1190", "Initial Access", "Exploit Public-Facing Application",
                          "Apache ActiveMQ ClassInfo deserialization RCE"),

    # Linux LPE
    "CVE-2021-3156": _t("T1068", "Privilege Escalation", "Exploitation for Privilege Escalation",
                         "sudo Baron Samedit — heap overflow in sudoedit"),
    "CVE-2021-4034": _t("T1068", "Privilege Escalation", "Exploitation for Privilege Escalation",
                         "PwnKit — pkexec local privilege escalation"),
    "CVE-2022-0847": _t("T1068", "Privilege Escalation", "Exploitation for Privilege Escalation",
                         "Dirty Pipe — Linux kernel arbitrary file write LPE"),

    # SSH
    "CVE-2023-38408": _t("T1210", "Lateral Movement", "Exploitation of Remote Services",
                          "OpenSSH ssh-agent PKCS#11 RCE"),
    "CVE-2024-6387":  _t("T1210", "Lateral Movement", "Exploitation of Remote Services",
                          "regreSSHion — OpenSSH pre-auth RCE (signal handler race)"),

    # GitLab
    "CVE-2021-22205": _t("T1190", "Initial Access", "Exploit Public-Facing Application",
                          "GitLab unauthenticated RCE via ExifTool"),

    # VMware
    "CVE-2021-21972": _t("T1190", "Initial Access", "Exploit Public-Facing Application",
                          "VMware vCenter unauthorized file upload RCE"),
    "CVE-2021-22005": _t("T1190", "Initial Access", "Exploit Public-Facing Application",
                          "VMware vCenter Log4Shell"),

    # VPN
    "CVE-2018-13379": _t("T1078", "Initial Access", "Valid Accounts",
                          "Fortinet FortiOS SSL VPN credential exposure", sub=".001"),
    "CVE-2019-11510": _t("T1078", "Initial Access", "Valid Accounts",
                          "Pulse Secure VPN arbitrary file read → credential theft", sub=".001"),
    "CVE-2019-19781": _t("T1190", "Initial Access", "Exploit Public-Facing Application",
                          "Citrix ADC / NetScaler path traversal RCE"),
}


# ── Port/service → ATT&CK mapping ─────────────────────────────────────────────

SERVICE_MAP: dict[str, ATTACKTag] = {
    "rdp":            _t("T1021", "Lateral Movement",      "Remote Services", sub=".001",
                          description="Open RDP — lateral movement vector"),
    "ssh":            _t("T1021", "Lateral Movement",      "Remote Services", sub=".004",
                          description="Open SSH — lateral movement / initial access vector"),
    "smb":            _t("T1021", "Lateral Movement",      "Remote Services", sub=".002",
                          description="Open SMB — file sharing and lateral movement"),
    "telnet":         _t("T1021", "Lateral Movement",      "Remote Services",
                          description="Open Telnet — cleartext remote access (insecure)"),
    "ftp":            _t("T1071", "Command and Control",   "Application Layer Protocol", sub=".002",
                          description="Open FTP — cleartext file transfer / C2 channel"),
    "vnc":            _t("T1021", "Lateral Movement",      "Remote Services", sub=".005",
                          description="Open VNC — remote desktop lateral movement"),
    "mysql":          _t("T1190", "Initial Access",        "Exploit Public-Facing Application",
                          description="Exposed MySQL — database direct access risk"),
    "mssql":          _t("T1190", "Initial Access",        "Exploit Public-Facing Application",
                          description="Exposed MSSQL — xp_cmdshell / database access risk"),
    "postgresql":     _t("T1190", "Initial Access",        "Exploit Public-Facing Application",
                          description="Exposed PostgreSQL — database access risk"),
    "redis":          _t("T1190", "Initial Access",        "Exploit Public-Facing Application",
                          description="Unauthenticated Redis — config write / RCE risk"),
    "mongodb":        _t("T1190", "Initial Access",        "Exploit Public-Facing Application",
                          description="Unauthenticated MongoDB — data exfiltration risk"),
    "elasticsearch":  _t("T1190", "Initial Access",        "Exploit Public-Facing Application",
                          description="Unauthenticated Elasticsearch — data exfiltration"),
    "smtp":           _t("T1566", "Initial Access",        "Phishing",
                          description="Open SMTP relay — mail spoofing / phishing vector", sub=".001"),
    "dns":            _t("T1071", "Command and Control",   "Application Layer Protocol", sub=".004",
                          description="Exposed DNS — zone transfer / tunneling risk"),
    "http":           _t("T1190", "Initial Access",        "Exploit Public-Facing Application",
                          description="HTTP service — web application attack surface"),
    "https":          _t("T1190", "Initial Access",        "Exploit Public-Facing Application",
                          description="HTTPS service — web application attack surface"),
    "snmp":           _t("T1046", "Discovery",             "Network Service Discovery",
                          description="Open SNMP — network info disclosure / community string risk"),
    "netbios-ssn":    _t("T1021", "Lateral Movement",      "Remote Services", sub=".002",
                          description="NetBIOS — Windows name resolution / lateral movement"),
    "msrpc":          _t("T1021", "Lateral Movement",      "Remote Services",
                          description="MSRPC — Windows RPC lateral movement vector"),
}

# Port number fallback
PORT_MAP: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
    443: "https", 445: "smb", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http", 8443: "https",
    9200: "elasticsearch", 27017: "mongodb",
}

# ── Misconfiguration patterns ─────────────────────────────────────────────────

MISCONFIG_MAP: dict[str, ATTACKTag] = {
    "default_credentials":   _t("T1078", "Initial Access", "Valid Accounts", sub=".001",
                                 description="Default credentials in use"),
    "weak_password":         _t("T1110", "Credential Access", "Brute Force", sub=".001",
                                 description="Weak or guessable password"),
    "anonymous_access":      _t("T1078", "Initial Access", "Valid Accounts", sub=".001",
                                 description="Anonymous/unauthenticated access permitted"),
    "ssl_weak_cipher":       _t("T1557", "Credential Access", "Adversary-in-the-Middle",
                                 description="Weak TLS cipher allows interception"),
    "ssl_expired_cert":      _t("T1557", "Credential Access", "Adversary-in-the-Middle",
                                 description="Expired certificate — client validation bypass risk"),
    "info_disclosure":       _t("T1082", "Discovery", "System Information Discovery",
                                 description="Service banner / error page reveals version info"),
    "directory_listing":     _t("T1083", "Discovery", "File and Directory Discovery",
                                 description="Web server directory listing enabled"),
    "open_redirect":         _t("T1566", "Initial Access", "Phishing", sub=".003",
                                 description="Open redirect — phishing / token theft vector"),
}


# ── Public API ─────────────────────────────────────────────────────────────────

class MITREMapper:
    """Tag security findings with MITRE ATT&CK techniques."""

    @staticmethod
    def from_cve(cve_id: str) -> ATTACKTag | None:
        return CVE_MAP.get(cve_id.upper())

    @staticmethod
    def from_service(service: str, port: int | None = None) -> ATTACKTag | None:
        svc = service.lower().replace("-", "")
        if svc in SERVICE_MAP:
            return SERVICE_MAP[svc]
        if port and port in PORT_MAP:
            return SERVICE_MAP.get(PORT_MAP[port])
        return None

    @staticmethod
    def from_misconfig(pattern: str) -> ATTACKTag | None:
        return MISCONFIG_MAP.get(pattern.lower())

    @staticmethod
    def tag_finding(title: str, description: str, cve_ids: list[str] | None = None,
                    service: str = "", port: int | None = None) -> list[ATTACKTag]:
        """
        Return all ATT&CK tags applicable to a finding.
        Checks CVE map first, then service map, then keyword heuristics.
        """
        tags: list[ATTACKTag] = []
        seen: set[str] = set()

        def _add(tag: ATTACKTag | None) -> None:
            if tag and tag.full_id not in seen:
                tags.append(tag)
                seen.add(tag.full_id)

        # CVE-based
        for cve_id in (cve_ids or []):
            _add(MITREMapper.from_cve(cve_id))

        # Service-based
        if service:
            _add(MITREMapper.from_service(service, port))
        elif port:
            _add(MITREMapper.from_service("", port))

        # Keyword heuristics on title + description
        text = f"{title} {description}".lower()
        for pattern, tag in MISCONFIG_MAP.items():
            if pattern.replace("_", " ") in text or pattern in text:
                _add(tag)

        return tags
