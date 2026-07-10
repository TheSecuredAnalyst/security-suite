"""Phishing simulation module for security awareness training."""

from modules.phishing.campaign import PhishingCampaign
from modules.phishing.server import PhishingServer
from modules.phishing.templates import TemplateManager
from modules.phishing.tracker import ClickTracker

__all__ = [
    "PhishingCampaign",
    "TemplateManager",
    "PhishingServer",
    "ClickTracker",
]
