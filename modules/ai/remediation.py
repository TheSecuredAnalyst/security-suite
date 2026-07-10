"""Remediation knowledge base and guidance engine."""

from dataclasses import dataclass, field

from core.logger import get_logger
from core.models import Finding


@dataclass
class RemediationStep:
    """A single remediation step."""
    order: int
    action: str
    details: str
    code_example: str | None = None
    verification: str | None = None


@dataclass
class RemediationGuide:
    """Complete remediation guidance for a finding type."""
    finding_pattern: str  # Pattern to match finding titles
    title: str
    description: str
    effort: str  # Low, Medium, High
    priority: str  # Immediate, Short-term, Long-term
    steps: list[RemediationStep] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    prevention: str = ""


class RemediationEngine:
    """Engine for generating remediation guidance."""

    # Knowledge base of remediation guides
    KNOWLEDGE_BASE: list[RemediationGuide] = [
        # SQL Injection
        RemediationGuide(
            finding_pattern="sql injection",
            title="SQL Injection Remediation",
            description="SQL injection allows attackers to execute arbitrary SQL commands",
            effort="Medium",
            priority="Immediate",
            steps=[
                RemediationStep(
                    order=1,
                    action="Use Parameterized Queries",
                    details="Replace string concatenation with parameterized/prepared statements",
                    code_example="""# Python - WRONG
query = f"SELECT * FROM users WHERE id = {user_id}"

# Python - CORRECT
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Node.js - CORRECT
db.query("SELECT * FROM users WHERE id = $1", [userId])""",
                    verification="Test with SQLi payloads like ' OR '1'='1 - should not alter query behavior",
                ),
                RemediationStep(
                    order=2,
                    action="Implement Input Validation",
                    details="Validate and sanitize all user inputs before processing",
                    code_example="""# Validate expected format
import re
if not re.match(r'^[0-9]+$', user_id):
    raise ValueError("Invalid user ID format")""",
                ),
                RemediationStep(
                    order=3,
                    action="Apply Least Privilege",
                    details="Database accounts should have minimal required permissions",
                    verification="Verify DB user cannot DROP tables or access other databases",
                ),
                RemediationStep(
                    order=4,
                    action="Enable WAF Rules",
                    details="Configure Web Application Firewall to block SQLi patterns",
                ),
            ],
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/89.html",
            ],
            prevention="Use ORMs or query builders that handle parameterization automatically",
        ),

        # XSS
        RemediationGuide(
            finding_pattern="xss",
            title="Cross-Site Scripting (XSS) Remediation",
            description="XSS allows attackers to inject malicious scripts into web pages",
            effort="Medium",
            priority="Immediate",
            steps=[
                RemediationStep(
                    order=1,
                    action="Encode Output",
                    details="HTML-encode all user-supplied data before rendering",
                    code_example="""# Python/Jinja2 - auto-escaping
{{ user_input }}  # Automatically escaped

# JavaScript - use textContent instead of innerHTML
element.textContent = userInput;  // Safe
element.innerHTML = userInput;    // Dangerous""",
                ),
                RemediationStep(
                    order=2,
                    action="Implement Content Security Policy",
                    details="Add CSP headers to prevent inline script execution",
                    code_example="""Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'""",
                    verification="Browser console should show CSP violations for injected scripts",
                ),
                RemediationStep(
                    order=3,
                    action="Sanitize Rich Text Input",
                    details="Use a whitelist-based HTML sanitizer for rich text fields",
                    code_example="""# Python with bleach
import bleach
clean_html = bleach.clean(user_html, tags=['p', 'b', 'i', 'a'], attributes={'a': ['href']})""",
                ),
                RemediationStep(
                    order=4,
                    action="Set HttpOnly Cookie Flag",
                    details="Prevent JavaScript access to session cookies",
                    code_example="Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict",
                ),
            ],
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/79.html",
            ],
            prevention="Use modern frameworks with auto-escaping (React, Vue, Angular)",
        ),

        # Missing Security Headers
        RemediationGuide(
            finding_pattern="security header",
            title="Security Headers Configuration",
            description="Missing security headers leave the application vulnerable to various attacks",
            effort="Low",
            priority="Short-term",
            steps=[
                RemediationStep(
                    order=1,
                    action="Add HSTS Header",
                    details="Force HTTPS connections",
                    code_example="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                ),
                RemediationStep(
                    order=2,
                    action="Add CSP Header",
                    details="Control resource loading",
                    code_example="Content-Security-Policy: default-src 'self'; script-src 'self'",
                ),
                RemediationStep(
                    order=3,
                    action="Add X-Frame-Options",
                    details="Prevent clickjacking",
                    code_example="X-Frame-Options: DENY",
                ),
                RemediationStep(
                    order=4,
                    action="Add X-Content-Type-Options",
                    details="Prevent MIME sniffing",
                    code_example="X-Content-Type-Options: nosniff",
                ),
            ],
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                "https://securityheaders.com/",
            ],
            prevention="Use a security headers middleware in your web framework",
        ),

        # Exposed Sensitive Files
        RemediationGuide(
            finding_pattern="exposed|disclosure|sensitive",
            title="Sensitive Data Exposure Remediation",
            description="Sensitive files or information exposed to unauthorized access",
            effort="Low",
            priority="Immediate",
            steps=[
                RemediationStep(
                    order=1,
                    action="Remove or Restrict Access",
                    details="Delete unnecessary files or configure access controls",
                    code_example="""# Nginx - block sensitive files
location ~ /\\.(git|env|htaccess) {
    deny all;
    return 404;
}""",
                ),
                RemediationStep(
                    order=2,
                    action="Move Files Outside Web Root",
                    details="Configuration files should not be in publicly accessible directories",
                ),
                RemediationStep(
                    order=3,
                    action="Review Directory Listings",
                    details="Disable directory listing in web server configuration",
                    code_example="""# Nginx
autoindex off;

# Apache
Options -Indexes""",
                ),
                RemediationStep(
                    order=4,
                    action="Audit File Permissions",
                    details="Ensure proper file permissions (e.g., 640 for configs)",
                    verification="Run: find /var/www -type f -perm /o+r -name '*.env'",
                ),
            ],
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/",
            ],
            prevention="Add sensitive file patterns to .gitignore and deployment scripts",
        ),

        # SSL/TLS Issues
        RemediationGuide(
            finding_pattern="ssl|tls|certificate",
            title="SSL/TLS Configuration Remediation",
            description="SSL/TLS misconfiguration weakens transport security",
            effort="Medium",
            priority="Short-term",
            steps=[
                RemediationStep(
                    order=1,
                    action="Disable Legacy Protocols",
                    details="Disable SSLv3, TLS 1.0, and TLS 1.1",
                    code_example="""# Nginx
ssl_protocols TLSv1.2 TLSv1.3;

# Apache
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1""",
                ),
                RemediationStep(
                    order=2,
                    action="Configure Strong Ciphers",
                    details="Use only strong cipher suites",
                    code_example="""ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers on;""",
                ),
                RemediationStep(
                    order=3,
                    action="Renew Expiring Certificates",
                    details="Set up automatic certificate renewal with Let's Encrypt",
                    code_example="certbot renew --dry-run",
                    verification="Check certificate expiry: echo | openssl s_client -connect domain:443 2>/dev/null | openssl x509 -noout -dates",
                ),
                RemediationStep(
                    order=4,
                    action="Enable OCSP Stapling",
                    details="Improve certificate validation performance",
                    code_example="""ssl_stapling on;
ssl_stapling_verify on;""",
                ),
            ],
            references=[
                "https://ssl-config.mozilla.org/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            ],
            prevention="Use Mozilla SSL Configuration Generator for new deployments",
        ),

        # Open Ports/Services
        RemediationGuide(
            finding_pattern="port|service|exposed",
            title="Exposed Service Hardening",
            description="Unnecessary or misconfigured services increase attack surface",
            effort="Medium",
            priority="Short-term",
            steps=[
                RemediationStep(
                    order=1,
                    action="Identify Required Services",
                    details="Document which services are business-critical",
                ),
                RemediationStep(
                    order=2,
                    action="Disable Unnecessary Services",
                    details="Stop and disable services not required for operation",
                    code_example="""# Linux
systemctl stop <service>
systemctl disable <service>""",
                ),
                RemediationStep(
                    order=3,
                    action="Configure Firewall Rules",
                    details="Implement allowlist-based firewall rules",
                    code_example="""# UFW example
ufw default deny incoming
ufw allow from 10.0.0.0/8 to any port 22
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable""",
                ),
                RemediationStep(
                    order=4,
                    action="Implement Network Segmentation",
                    details="Place sensitive services in isolated network segments",
                ),
            ],
            references=[
                "https://www.cisecurity.org/controls/",
            ],
            prevention="Regular port scans and service audits as part of security monitoring",
        ),
    ]

    def __init__(self):
        self.logger = get_logger("ai.remediation")

    def get_remediation(self, finding: Finding) -> RemediationGuide | None:
        """Get remediation guide for a finding.

        Args:
            finding: The finding to get remediation for

        Returns:
            RemediationGuide if found, None otherwise
        """
        title_lower = finding.title.lower()
        description_lower = finding.description.lower()

        for guide in self.KNOWLEDGE_BASE:
            pattern = guide.finding_pattern.lower()
            if pattern in title_lower or pattern in description_lower:
                return guide

        return None

    def get_all_remediations(self, findings: list[Finding]) -> dict[str, RemediationGuide]:
        """Get remediation guides for multiple findings.

        Args:
            findings: List of findings

        Returns:
            Dict mapping finding titles to remediation guides
        """
        result = {}
        for finding in findings:
            guide = self.get_remediation(finding)
            if guide:
                result[finding.title] = guide
        return result

    def format_remediation(self, guide: RemediationGuide) -> str:
        """Format remediation guide as readable text.

        Args:
            guide: The remediation guide

        Returns:
            Formatted string
        """
        lines = [
            f"# {guide.title}",
            "",
            f"**Description:** {guide.description}",
            f"**Effort:** {guide.effort} | **Priority:** {guide.priority}",
            "",
            "## Remediation Steps",
            "",
        ]

        for step in guide.steps:
            lines.append(f"### Step {step.order}: {step.action}")
            lines.append(step.details)
            if step.code_example:
                lines.append("\n```")
                lines.append(step.code_example)
                lines.append("```\n")
            if step.verification:
                lines.append(f"**Verification:** {step.verification}")
            lines.append("")

        if guide.prevention:
            lines.append("## Prevention")
            lines.append(guide.prevention)
            lines.append("")

        if guide.references:
            lines.append("## References")
            for ref in guide.references:
                lines.append(f"- {ref}")

        return "\n".join(lines)
