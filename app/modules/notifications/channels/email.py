import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.modules.notifications.channels.base import BaseChannel
from app.modules.notifications.schemas import AlertPayload
from app.core.config import settings


# Severity → color mapping for HTML emails
SEVERITY_COLORS = {
    "critical": "#DC2626",  # Red
    "high": "#EA580C",       # Orange
    "medium": "#CA8A04",     # Yellow
    "low": "#2563EB",        # Blue
}

LEVEL_LABELS = {
    1: "Auto-Fix (Level 1)",
    2: "Fix + Alert (Level 2)",
    3: "Alert Only (Level 3)",
}


def _build_html_email(payload: AlertPayload) -> str:
    """Builds a clean HTML email for the incident alert."""
    color = SEVERITY_COLORS.get(payload.severity, "#6B7280")
    level_label = LEVEL_LABELS.get(payload.action_level, "Unknown")
    
    context_rows = ""
    if payload.context:
        for key, value in payload.context.items():
            context_rows += f"""
            <tr>
                <td style="padding:8px 12px; border-bottom:1px solid #E5E7EB; color:#6B7280; font-weight:600;">{key}</td>
                <td style="padding:8px 12px; border-bottom:1px solid #E5E7EB; font-family:monospace;">{value}</td>
            </tr>"""

    remediation_section = ""
    if payload.remediation_status:
        rem_color = "#16A34A" if payload.remediation_status == "executed" else "#DC2626"
        remediation_section = f"""
        <div style="margin-top:16px; padding:12px; background:{rem_color}15; border-left:4px solid {rem_color}; border-radius:4px;">
            <strong>Remediation:</strong> {payload.remediation_status.upper()}
        </div>"""
    
    detected_str = payload.detected_at.strftime("%Y-%m-%d %H:%M:%S UTC") if payload.detected_at else "N/A"

    return f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width:600px; margin:0 auto;">
        
        <!-- Header -->
        <div style="background:{color}; padding:20px 24px; border-radius:8px 8px 0 0;">
            <h1 style="color:white; margin:0; font-size:20px;">
                SecOps Alert — {payload.severity.upper()}
            </h1>
            <p style="color:rgba(255,255,255,0.85); margin:4px 0 0 0; font-size:14px;">
                {payload.rule_name}
            </p>
        </div>
        
        <!-- Body -->
        <div style="background:#FFFFFF; padding:24px; border:1px solid #E5E7EB; border-top:none;">
            
            <p style="margin:0 0 16px 0; color:#374151; font-size:15px;">
                {payload.description}
            </p>
            
            <!-- Info Table -->
            <table style="width:100%; border-collapse:collapse; margin-bottom:16px;">
                <tr>
                    <td style="padding:8px 12px; border-bottom:1px solid #E5E7EB; color:#6B7280; font-weight:600;">Server</td>
                    <td style="padding:8px 12px; border-bottom:1px solid #E5E7EB;">{payload.server_hostname} ({payload.server_ip})</td>
                </tr>
                <tr>
                    <td style="padding:8px 12px; border-bottom:1px solid #E5E7EB; color:#6B7280; font-weight:600;">Severity</td>
                    <td style="padding:8px 12px; border-bottom:1px solid #E5E7EB;">
                        <span style="background:{color}; color:white; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600;">
                            {payload.severity.upper()}
                        </span>
                    </td>
                </tr>
                <tr>
                    <td style="padding:8px 12px; border-bottom:1px solid #E5E7EB; color:#6B7280; font-weight:600;">Action Level</td>
                    <td style="padding:8px 12px; border-bottom:1px solid #E5E7EB;">{level_label}</td>
                </tr>
                <tr>
                    <td style="padding:8px 12px; border-bottom:1px solid #E5E7EB; color:#6B7280; font-weight:600;">Detected At</td>
                    <td style="padding:8px 12px; border-bottom:1px solid #E5E7EB;">{detected_str}</td>
                </tr>
                {context_rows}
            </table>
            
            {remediation_section}
        </div>
        
        <!-- Footer -->
        <div style="background:#F9FAFB; padding:16px 24px; border:1px solid #E5E7EB; border-top:none; border-radius:0 0 8px 8px;">
            <p style="margin:0; color:#9CA3AF; font-size:12px;">
                SecOps Platform — Incident ID: {payload.incident_id}
            </p>
        </div>
    </div>
    """


class EmailChannel(BaseChannel):
    """
    Sends alert emails via SMTP using aiosmtplib (async).
    
    Configuration comes from .env / Settings:
    - SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD
    - SMTP_USE_TLS, ALERT_FROM_EMAIL
    
    Can be overridden per-notification via DB config.
    """

    def __init__(self, smtp_host=None, smtp_port=None, smtp_user=None, smtp_password=None):
        self.smtp_host = smtp_host or settings.SMTP_HOST
        self.smtp_port = smtp_port or settings.SMTP_PORT
        self.smtp_user = smtp_user or settings.SMTP_USER
        self.smtp_password = smtp_password or settings.SMTP_PASSWORD
        self.from_email = settings.ALERT_FROM_EMAIL or self.smtp_user

    async def send(self, payload: AlertPayload, recipients: list[str]) -> bool:
        """
        Sends an HTML email alert to all recipients.
        Returns True if sent successfully.
        """
        if not self.smtp_host or not recipients:
            print("   Email alert skipped: SMTP not configured or no recipients")
            return False

        try:
            # Build the email
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[SecOps {payload.severity.upper()}] {payload.rule_name} — {payload.server_hostname}"
            msg["From"] = self.from_email
            msg["To"] = ", ".join(recipients)

            # Plain text fallback
            plain_text = (
                f"SecOps Alert — {payload.severity.upper()}\n\n"
                f"Rule: {payload.rule_name}\n"
                f"Server: {payload.server_hostname} ({payload.server_ip})\n"
                f"Description: {payload.description}\n"
                f"Detected: {payload.detected_at}\n"
                f"Incident ID: {payload.incident_id}\n"
            )
            msg.attach(MIMEText(plain_text, "plain"))

            # HTML version
            html = _build_html_email(payload)
            msg.attach(MIMEText(html, "html"))

            # Send async
            await aiosmtplib.send(
                msg,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                start_tls=settings.SMTP_USE_TLS,
            )

            print(f"   Email alert sent to {len(recipients)} recipients")
            return True

        except Exception as e:
            print(f"   Email alert failed: {e}")
            return False
