"""Phishing campaign management."""

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from core.config import get_settings
from core.logger import get_logger


class CampaignStatus(str, Enum):
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"


@dataclass
class CampaignTarget:
    """Individual target in a campaign."""
    email: str
    first_name: str = ""
    last_name: str = ""
    department: str = ""
    tracking_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    email_sent: bool = False
    email_opened: bool = False
    link_clicked: bool = False
    credentials_submitted: bool = False
    sent_at: datetime | None = None
    opened_at: datetime | None = None
    clicked_at: datetime | None = None
    submitted_at: datetime | None = None


@dataclass
class PhishingCampaign:
    """Phishing campaign for security awareness training."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    status: CampaignStatus = CampaignStatus.DRAFT
    email_template_id: str = ""
    landing_template_id: str = ""
    sender_email: str = ""
    sender_name: str = ""
    phishing_url: str = ""
    targets: list[CampaignTarget] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    custom_variables: dict = field(default_factory=dict)

    @property
    def total_targets(self) -> int:
        return len(self.targets)

    @property
    def emails_sent(self) -> int:
        return sum(1 for t in self.targets if t.email_sent)

    @property
    def emails_opened(self) -> int:
        return sum(1 for t in self.targets if t.email_opened)

    @property
    def links_clicked(self) -> int:
        return sum(1 for t in self.targets if t.link_clicked)

    @property
    def credentials_submitted(self) -> int:
        return sum(1 for t in self.targets if t.credentials_submitted)

    @property
    def open_rate(self) -> float:
        if self.emails_sent == 0:
            return 0.0
        return (self.emails_opened / self.emails_sent) * 100

    @property
    def click_rate(self) -> float:
        if self.emails_sent == 0:
            return 0.0
        return (self.links_clicked / self.emails_sent) * 100

    @property
    def submission_rate(self) -> float:
        if self.emails_sent == 0:
            return 0.0
        return (self.credentials_submitted / self.emails_sent) * 100

    def add_target(self, email: str, first_name: str = "", last_name: str = "", department: str = "") -> CampaignTarget:
        """Add a target to the campaign."""
        target = CampaignTarget(
            email=email,
            first_name=first_name,
            last_name=last_name,
            department=department,
        )
        self.targets.append(target)
        return target

    def add_targets_from_csv(self, csv_content: str) -> int:
        """Add targets from CSV content. Returns count of targets added."""
        import csv
        from io import StringIO

        reader = csv.DictReader(StringIO(csv_content))
        count = 0

        for row in reader:
            email = row.get("email", "").strip()
            if email:
                self.add_target(
                    email=email,
                    first_name=row.get("first_name", "").strip(),
                    last_name=row.get("last_name", "").strip(),
                    department=row.get("department", "").strip(),
                )
                count += 1

        return count

    def get_target_by_tracking_id(self, tracking_id: str) -> CampaignTarget | None:
        """Get target by tracking ID."""
        for target in self.targets:
            if target.tracking_id == tracking_id:
                return target
        return None

    def get_statistics(self) -> dict:
        """Get campaign statistics."""
        return {
            "total_targets": self.total_targets,
            "emails_sent": self.emails_sent,
            "emails_opened": self.emails_opened,
            "links_clicked": self.links_clicked,
            "credentials_submitted": self.credentials_submitted,
            "open_rate": f"{self.open_rate:.1f}%",
            "click_rate": f"{self.click_rate:.1f}%",
            "submission_rate": f"{self.submission_rate:.1f}%",
        }

    def to_dict(self) -> dict:
        """Convert campaign to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "email_template_id": self.email_template_id,
            "landing_template_id": self.landing_template_id,
            "sender_email": self.sender_email,
            "sender_name": self.sender_name,
            "phishing_url": self.phishing_url,
            "targets": [
                {
                    "email": t.email,
                    "first_name": t.first_name,
                    "last_name": t.last_name,
                    "department": t.department,
                    "tracking_id": t.tracking_id,
                    "email_sent": t.email_sent,
                    "email_opened": t.email_opened,
                    "link_clicked": t.link_clicked,
                    "credentials_submitted": t.credentials_submitted,
                    "sent_at": t.sent_at.isoformat() if t.sent_at else None,
                    "opened_at": t.opened_at.isoformat() if t.opened_at else None,
                    "clicked_at": t.clicked_at.isoformat() if t.clicked_at else None,
                    "submitted_at": t.submitted_at.isoformat() if t.submitted_at else None,
                }
                for t in self.targets
            ],
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "custom_variables": self.custom_variables,
            "statistics": self.get_statistics(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PhishingCampaign":
        """Create campaign from dictionary."""
        campaign = cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            status=CampaignStatus(data["status"]),
            email_template_id=data["email_template_id"],
            landing_template_id=data["landing_template_id"],
            sender_email=data["sender_email"],
            sender_name=data["sender_name"],
            phishing_url=data["phishing_url"],
            custom_variables=data.get("custom_variables", {}),
        )

        for t in data.get("targets", []):
            target = CampaignTarget(
                email=t["email"],
                first_name=t.get("first_name", ""),
                last_name=t.get("last_name", ""),
                department=t.get("department", ""),
                tracking_id=t["tracking_id"],
                email_sent=t.get("email_sent", False),
                email_opened=t.get("email_opened", False),
                link_clicked=t.get("link_clicked", False),
                credentials_submitted=t.get("credentials_submitted", False),
            )
            campaign.targets.append(target)

        return campaign


class CampaignManager:
    """Manage phishing campaigns."""

    def __init__(self, data_dir: Path | None = None):
        self.logger = get_logger("phishing.campaigns")
        self.data_dir = data_dir or (get_settings().data_dir / "campaigns")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.campaigns: dict[str, PhishingCampaign] = {}
        self._load_campaigns()

    def _load_campaigns(self) -> None:
        """Load campaigns from disk."""
        for campaign_file in self.data_dir.glob("*.json"):
            try:
                with open(campaign_file) as f:
                    data = json.load(f)
                    campaign = PhishingCampaign.from_dict(data)
                    self.campaigns[campaign.id] = campaign
            except Exception as e:
                self.logger.error(f"Failed to load campaign {campaign_file}: {e}")

    def save_campaign(self, campaign: PhishingCampaign) -> None:
        """Save campaign to disk."""
        with open(self.data_dir / f"{campaign.id}.json", "w") as f:
            json.dump(campaign.to_dict(), f, indent=2)
        self.campaigns[campaign.id] = campaign

    def get_campaign(self, campaign_id: str) -> PhishingCampaign | None:
        """Get campaign by ID."""
        return self.campaigns.get(campaign_id)

    def list_campaigns(self) -> list[PhishingCampaign]:
        """List all campaigns."""
        return list(self.campaigns.values())

    def delete_campaign(self, campaign_id: str) -> bool:
        """Delete a campaign."""
        if campaign_id not in self.campaigns:
            return False

        campaign_file = self.data_dir / f"{campaign_id}.json"
        if campaign_file.exists():
            campaign_file.unlink()

        del self.campaigns[campaign_id]
        return True

    def create_campaign(
        self,
        name: str,
        email_template_id: str,
        landing_template_id: str,
        sender_email: str,
        sender_name: str,
        phishing_url: str,
        **kwargs
    ) -> PhishingCampaign:
        """Create a new campaign."""
        campaign = PhishingCampaign(
            name=name,
            email_template_id=email_template_id,
            landing_template_id=landing_template_id,
            sender_email=sender_email,
            sender_name=sender_name,
            phishing_url=phishing_url,
            **kwargs
        )
        self.save_campaign(campaign)
        return campaign
