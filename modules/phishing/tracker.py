"""Click and event tracking for phishing campaigns."""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.logger import get_logger
from modules.phishing.campaign import CampaignTarget, PhishingCampaign


@dataclass
class TrackingEvent:
    """A tracked event in a campaign."""
    campaign_id: str
    target_email: str
    event_type: str  # "open", "click", "submit"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ip_address: str | None = None
    user_agent: str | None = None
    metadata: dict = field(default_factory=dict)


class ClickTracker:
    """Track and analyze phishing campaign events."""

    def __init__(self):
        self.logger = get_logger("phishing.tracker")
        self.events: list[TrackingEvent] = []

    def track_open(
        self,
        campaign: PhishingCampaign,
        target: CampaignTarget,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> TrackingEvent:
        """Track an email open event."""
        event = TrackingEvent(
            campaign_id=campaign.id,
            target_email=target.email,
            event_type="open",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self.events.append(event)
        self.logger.info(f"Tracked open: {target.email}")
        return event

    def track_click(
        self,
        campaign: PhishingCampaign,
        target: CampaignTarget,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> TrackingEvent:
        """Track a link click event."""
        event = TrackingEvent(
            campaign_id=campaign.id,
            target_email=target.email,
            event_type="click",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self.events.append(event)
        self.logger.warning(f"Tracked click: {target.email}")
        return event

    def track_submission(
        self,
        campaign: PhishingCampaign,
        target: CampaignTarget,
        fields_submitted: list[str],
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> TrackingEvent:
        """Track a credential submission event."""
        event = TrackingEvent(
            campaign_id=campaign.id,
            target_email=target.email,
            event_type="submit",
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"fields_submitted": fields_submitted},
        )
        self.events.append(event)
        self.logger.warning(f"Tracked submission: {target.email}")
        return event

    def get_campaign_events(self, campaign_id: str) -> list[TrackingEvent]:
        """Get all events for a campaign."""
        return [e for e in self.events if e.campaign_id == campaign_id]

    def get_target_events(self, target_email: str) -> list[TrackingEvent]:
        """Get all events for a specific target."""
        return [e for e in self.events if e.target_email == target_email]

    def generate_report(self, campaign: PhishingCampaign) -> dict:
        """Generate a tracking report for a campaign."""
        events = self.get_campaign_events(campaign.id)

        # Time analysis
        time_to_click = []
        for target in campaign.targets:
            if target.sent_at and target.clicked_at:
                delta = (target.clicked_at - target.sent_at).total_seconds()
                time_to_click.append(delta)

        avg_time_to_click = sum(time_to_click) / len(time_to_click) if time_to_click else 0

        # Department breakdown
        dept_stats = {}
        for target in campaign.targets:
            dept = target.department or "Unknown"
            if dept not in dept_stats:
                dept_stats[dept] = {"total": 0, "clicked": 0, "submitted": 0}
            dept_stats[dept]["total"] += 1
            if target.link_clicked:
                dept_stats[dept]["clicked"] += 1
            if target.credentials_submitted:
                dept_stats[dept]["submitted"] += 1

        return {
            "campaign_name": campaign.name,
            "campaign_id": campaign.id,
            "status": campaign.status.value,
            "summary": {
                "total_targets": campaign.total_targets,
                "emails_sent": campaign.emails_sent,
                "emails_opened": campaign.emails_opened,
                "links_clicked": campaign.links_clicked,
                "credentials_submitted": campaign.credentials_submitted,
            },
            "rates": {
                "open_rate": f"{campaign.open_rate:.1f}%",
                "click_rate": f"{campaign.click_rate:.1f}%",
                "submission_rate": f"{campaign.submission_rate:.1f}%",
            },
            "timing": {
                "average_time_to_click_seconds": avg_time_to_click,
                "fastest_click_seconds": min(time_to_click) if time_to_click else 0,
                "slowest_click_seconds": max(time_to_click) if time_to_click else 0,
            },
            "department_breakdown": dept_stats,
            "event_timeline": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "type": e.event_type,
                    "target": e.target_email,
                }
                for e in sorted(events, key=lambda x: x.timestamp)
            ],
        }
