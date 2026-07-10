"""Generic webhook exporter for notifications and integrations."""


import httpx

from modules.siem.base import SIEMEvent, SIEMExporter


class WebhookExporter(SIEMExporter):
    """Export events via webhooks (Slack, Discord, PagerDuty, custom)."""

    def __init__(
        self,
        url: str,
        method: str = "POST",
        headers: dict | None = None,
        auth_token: str | None = None,
        auth_header: str = "Authorization",
        format: str = "json",  # json, slack, discord, pagerduty
        min_severity: str = "low",  # Only send events at or above this severity
        timeout: float = 10.0,
    ):
        """Initialize webhook exporter.

        Args:
            url: Webhook URL
            method: HTTP method
            headers: Custom headers
            auth_token: Authentication token
            auth_header: Header name for auth token
            format: Payload format (json, slack, discord, pagerduty)
            min_severity: Minimum severity to trigger webhook
            timeout: Request timeout
        """
        super().__init__()
        self.url = url
        self.method = method.upper()
        self.custom_headers = headers or {}
        self.auth_token = auth_token
        self.auth_header = auth_header
        self.format = format.lower()
        self.min_severity = min_severity.lower()
        self.timeout = timeout

        self._severity_order = ["info", "low", "medium", "high", "critical"]

    def _should_send(self, event: SIEMEvent) -> bool:
        """Check if event meets severity threshold."""
        event_idx = self._severity_order.index(event.severity.lower())
        min_idx = self._severity_order.index(self.min_severity)
        return event_idx >= min_idx

    def _get_headers(self) -> dict:
        """Get request headers."""
        headers = {
            "Content-Type": "application/json",
            **self.custom_headers,
        }

        if self.auth_token:
            if self.format == "pagerduty":
                headers["Authorization"] = f"Token token={self.auth_token}"
            else:
                headers[self.auth_header] = f"Bearer {self.auth_token}"

        return headers

    def _format_payload(self, event: SIEMEvent) -> dict:
        """Format event payload based on target format."""
        if self.format == "slack":
            return self._format_slack(event)
        elif self.format == "discord":
            return self._format_discord(event)
        elif self.format == "pagerduty":
            return self._format_pagerduty(event)
        else:
            return event.to_dict()

    def _format_slack(self, event: SIEMEvent) -> dict:
        """Format as Slack message."""
        color_map = {
            "critical": "#FF0000",
            "high": "#FF6600",
            "medium": "#FFCC00",
            "low": "#00CCFF",
            "info": "#808080",
        }

        color = color_map.get(event.severity.lower(), "#808080")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔒 Security Alert: {event.event_type.value}",
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n{event.target}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{event.severity.upper()}"},
                    {"type": "mrkdwn", "text": f"*Module:*\n{event.module}"},
                    {"type": "mrkdwn", "text": f"*Time:*\n{event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"},
                ]
            },
        ]

        if event.finding_title:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Finding:* {event.finding_title}\n{event.finding_description or ''}",
                }
            })

        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks,
                }
            ]
        }

    def _format_discord(self, event: SIEMEvent) -> dict:
        """Format as Discord webhook message."""
        color_map = {
            "critical": 0xFF0000,
            "high": 0xFF6600,
            "medium": 0xFFCC00,
            "low": 0x00CCFF,
            "info": 0x808080,
        }

        color = color_map.get(event.severity.lower(), 0x808080)

        embed = {
            "title": f"🔒 {event.event_type.value}",
            "color": color,
            "timestamp": event.timestamp.isoformat(),
            "fields": [
                {"name": "Target", "value": event.target or "N/A", "inline": True},
                {"name": "Severity", "value": event.severity.upper(), "inline": True},
                {"name": "Module", "value": event.module or "N/A", "inline": True},
            ],
        }

        if event.finding_title:
            embed["fields"].append({
                "name": "Finding",
                "value": event.finding_title,
                "inline": False,
            })

        if event.finding_description:
            embed["description"] = event.finding_description[:500]

        return {"embeds": [embed]}

    def _format_pagerduty(self, event: SIEMEvent) -> dict:
        """Format as PagerDuty event."""
        severity_map = {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "info",
            "info": "info",
        }

        return {
            "routing_key": self.auth_token,
            "event_action": "trigger",
            "dedup_key": f"{event.target}-{event.event_type.value}-{event.finding_title or 'alert'}",
            "payload": {
                "summary": event.message or event.finding_title or "Security Alert",
                "severity": severity_map.get(event.severity.lower(), "info"),
                "source": event.target or "security-suite",
                "component": event.module,
                "group": "security-scans",
                "class": event.event_type.value,
                "custom_details": event.raw_data,
            },
        }

    async def export(self, event: SIEMEvent) -> bool:
        """Export event via webhook.

        Args:
            event: Event to export

        Returns:
            True if successful
        """
        if not self._should_send(event):
            self.logger.debug(f"Event below severity threshold: {event.severity}")
            return True  # Not an error, just filtered

        payload = self._format_payload(event)

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.request(
                    method=self.method,
                    url=self.url,
                    json=payload,
                    headers=self._get_headers(),
                )

                if response.status_code in [200, 201, 202, 204]:
                    self.logger.debug(f"Webhook delivered: {event.event_type}")
                    return True
                else:
                    self.logger.error(
                        f"Webhook error: {response.status_code} - {response.text}"
                    )
                    return False

        except Exception as e:
            self.logger.error(f"Webhook export failed: {e}")
            return False

    async def test_connection(self) -> bool:
        """Test webhook endpoint.

        Returns:
            True if reachable
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Send a test/ping request
                if self.format == "slack":
                    # Slack accepts empty payload for testing
                    response = await client.post(
                        self.url,
                        json={"text": "Security Suite connection test"},
                        headers=self._get_headers(),
                    )
                else:
                    # Just check if endpoint is reachable
                    response = await client.head(self.url)

                return response.status_code < 500

        except Exception as e:
            self.logger.error(f"Webhook test failed: {e}")
            return False

    def get_config_info(self) -> dict:
        """Get exporter configuration info."""
        return {
            "type": "webhook",
            "url": self.url[:50] + "..." if len(self.url) > 50 else self.url,
            "format": self.format,
            "min_severity": self.min_severity,
        }


# Convenience factory functions
def create_slack_webhook(webhook_url: str, min_severity: str = "medium") -> WebhookExporter:
    """Create Slack webhook exporter."""
    return WebhookExporter(
        url=webhook_url,
        format="slack",
        min_severity=min_severity,
    )


def create_discord_webhook(webhook_url: str, min_severity: str = "medium") -> WebhookExporter:
    """Create Discord webhook exporter."""
    return WebhookExporter(
        url=webhook_url,
        format="discord",
        min_severity=min_severity,
    )


def create_pagerduty_webhook(routing_key: str, min_severity: str = "high") -> WebhookExporter:
    """Create PagerDuty webhook exporter."""
    return WebhookExporter(
        url="https://events.pagerduty.com/v2/enqueue",
        format="pagerduty",
        auth_token=routing_key,
        min_severity=min_severity,
    )
