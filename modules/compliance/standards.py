"""Security standards and compliance frameworks."""

from dataclasses import dataclass, field
from enum import Enum


class ComplianceStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    NOT_APPLICABLE = "n/a"


@dataclass
class ControlCheck:
    """A single compliance control check."""
    id: str
    name: str
    description: str
    category: str
    severity: str  # critical, high, medium, low
    check_function: str | None = None  # Name of function to run
    remediation: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class SecurityStandard:
    """A security compliance standard/framework."""
    id: str
    name: str
    version: str
    description: str
    controls: list[ControlCheck] = field(default_factory=list)

    def get_control(self, control_id: str) -> ControlCheck | None:
        for control in self.controls:
            if control.id == control_id:
                return control
        return None


# OWASP Top 10 (2021)
OWASP_TOP_10 = SecurityStandard(
    id="owasp-top-10",
    name="OWASP Top 10",
    version="2021",
    description="OWASP Top 10 Web Application Security Risks",
    controls=[
        ControlCheck(
            id="A01",
            name="Broken Access Control",
            description="Restrictions on authenticated users are not properly enforced",
            category="Access Control",
            severity="critical",
            check_function="check_access_control",
            remediation="Implement proper access control mechanisms, deny by default",
            references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
        ),
        ControlCheck(
            id="A02",
            name="Cryptographic Failures",
            description="Failures related to cryptography leading to exposure of sensitive data",
            category="Cryptography",
            severity="critical",
            check_function="check_cryptography",
            remediation="Use strong encryption, proper key management, HTTPS everywhere",
            references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
        ),
        ControlCheck(
            id="A03",
            name="Injection",
            description="User-supplied data is not validated, filtered, or sanitized",
            category="Input Validation",
            severity="critical",
            check_function="check_injection",
            remediation="Use parameterized queries, input validation, escape output",
            references=["https://owasp.org/Top10/A03_2021-Injection/"],
        ),
        ControlCheck(
            id="A04",
            name="Insecure Design",
            description="Missing or ineffective control design",
            category="Design",
            severity="high",
            check_function="check_secure_design",
            remediation="Threat modeling, secure design patterns, reference architectures",
            references=["https://owasp.org/Top10/A04_2021-Insecure_Design/"],
        ),
        ControlCheck(
            id="A05",
            name="Security Misconfiguration",
            description="Missing security hardening or improperly configured permissions",
            category="Configuration",
            severity="high",
            check_function="check_security_config",
            remediation="Secure defaults, hardening guides, automated configuration checks",
            references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
        ),
        ControlCheck(
            id="A06",
            name="Vulnerable and Outdated Components",
            description="Using components with known vulnerabilities",
            category="Dependencies",
            severity="high",
            check_function="check_components",
            remediation="Regular updates, dependency scanning, remove unused components",
            references=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
        ),
        ControlCheck(
            id="A07",
            name="Identification and Authentication Failures",
            description="Incorrectly implemented authentication and session management",
            category="Authentication",
            severity="critical",
            check_function="check_authentication",
            remediation="Multi-factor auth, secure session management, strong passwords",
            references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
        ),
        ControlCheck(
            id="A08",
            name="Software and Data Integrity Failures",
            description="Code and infrastructure without integrity verification",
            category="Integrity",
            severity="high",
            check_function="check_integrity",
            remediation="Digital signatures, CI/CD security, integrity verification",
            references=["https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"],
        ),
        ControlCheck(
            id="A09",
            name="Security Logging and Monitoring Failures",
            description="Insufficient logging, detection, monitoring, and response",
            category="Logging",
            severity="medium",
            check_function="check_logging",
            remediation="Comprehensive logging, monitoring, alerting, incident response",
            references=["https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"],
        ),
        ControlCheck(
            id="A10",
            name="Server-Side Request Forgery (SSRF)",
            description="Application fetches remote resources without validating URLs",
            category="Input Validation",
            severity="high",
            check_function="check_ssrf",
            remediation="Validate URLs, allowlist destinations, network segmentation",
            references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
        ),
    ],
)


# CIS Controls v8
CIS_CONTROLS = SecurityStandard(
    id="cis-controls",
    name="CIS Critical Security Controls",
    version="8",
    description="Center for Internet Security Critical Security Controls",
    controls=[
        ControlCheck(
            id="CIS-1",
            name="Inventory and Control of Enterprise Assets",
            description="Actively manage all enterprise assets",
            category="Asset Management",
            severity="high",
            check_function="check_asset_inventory",
            remediation="Maintain accurate inventory, automated discovery, CMDB",
            references=["https://www.cisecurity.org/controls/inventory-and-control-of-enterprise-assets"],
        ),
        ControlCheck(
            id="CIS-2",
            name="Inventory and Control of Software Assets",
            description="Actively manage all software on the network",
            category="Software Management",
            severity="high",
            check_function="check_software_inventory",
            remediation="Software inventory, allowlisting, removal of unauthorized software",
            references=["https://www.cisecurity.org/controls/inventory-and-control-of-software-assets"],
        ),
        ControlCheck(
            id="CIS-3",
            name="Data Protection",
            description="Develop processes and technical controls to protect data",
            category="Data Security",
            severity="critical",
            check_function="check_data_protection",
            remediation="Data classification, encryption, DLP, access controls",
            references=["https://www.cisecurity.org/controls/data-protection"],
        ),
        ControlCheck(
            id="CIS-4",
            name="Secure Configuration of Enterprise Assets and Software",
            description="Establish and maintain secure configurations",
            category="Configuration",
            severity="high",
            check_function="check_secure_config",
            remediation="Hardening baselines, configuration management, CIS Benchmarks",
            references=["https://www.cisecurity.org/controls/secure-configuration-of-enterprise-assets-and-software"],
        ),
        ControlCheck(
            id="CIS-5",
            name="Account Management",
            description="Use processes and tools to assign and manage authorization",
            category="Identity",
            severity="critical",
            check_function="check_account_management",
            remediation="Centralized auth, least privilege, regular access reviews",
            references=["https://www.cisecurity.org/controls/account-management"],
        ),
        ControlCheck(
            id="CIS-6",
            name="Access Control Management",
            description="Use processes to create, assign, manage credentials and privileges",
            category="Access Control",
            severity="critical",
            check_function="check_access_control_mgmt",
            remediation="RBAC, MFA, privileged access management",
            references=["https://www.cisecurity.org/controls/access-control-management"],
        ),
        ControlCheck(
            id="CIS-7",
            name="Continuous Vulnerability Management",
            description="Continuously assess and remediate vulnerabilities",
            category="Vulnerability Management",
            severity="high",
            check_function="check_vuln_management",
            remediation="Regular scanning, risk-based prioritization, patching",
            references=["https://www.cisecurity.org/controls/continuous-vulnerability-management"],
        ),
        ControlCheck(
            id="CIS-8",
            name="Audit Log Management",
            description="Collect, alert, review, and retain audit logs",
            category="Logging",
            severity="medium",
            check_function="check_audit_logs",
            remediation="Centralized logging, SIEM, log retention policies",
            references=["https://www.cisecurity.org/controls/audit-log-management"],
        ),
    ],
)
