"""Phishing server for hosting landing pages and tracking."""

from collections.abc import Callable
from datetime import datetime, timezone

from aiohttp import web

from core.logger import get_logger
from modules.phishing.campaign import CampaignManager
from modules.phishing.templates import TemplateManager


class PhishingServer:
    """HTTP server for phishing landing pages and tracking."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        campaign_manager: CampaignManager | None = None,
        template_manager: TemplateManager | None = None,
    ):
        self.host = host
        self.port = port
        self.logger = get_logger("phishing.server")
        self.campaign_manager = campaign_manager or CampaignManager()
        self.template_manager = template_manager or TemplateManager()
        self.app: web.Application | None = None
        self.runner: web.AppRunner | None = None
        self._on_click_callbacks: list[Callable] = []
        self._on_submit_callbacks: list[Callable] = []

    def on_click(self, callback: Callable) -> None:
        """Register callback for link click events."""
        self._on_click_callbacks.append(callback)

    def on_submit(self, callback: Callable) -> None:
        """Register callback for form submission events."""
        self._on_submit_callbacks.append(callback)

    async def start(self) -> None:
        """Start the phishing server."""
        self.app = web.Application()

        # Routes
        self.app.router.add_get("/track/{campaign_id}/{tracking_id}", self._handle_track_open)
        self.app.router.add_get("/click/{campaign_id}/{tracking_id}", self._handle_click)
        self.app.router.add_get("/landing/{campaign_id}/{tracking_id}", self._handle_landing)
        self.app.router.add_post("/capture/{campaign_id}", self._handle_capture)
        self.app.router.add_get("/pixel/{campaign_id}/{tracking_id}.gif", self._handle_pixel)

        self.runner = web.AppRunner(self.app)
        await self.runner.setup()

        site = web.TCPSite(self.runner, self.host, self.port)
        await site.start()

        self.logger.info(f"Phishing server started on http://{self.host}:{self.port}")

    async def stop(self) -> None:
        """Stop the phishing server."""
        if self.runner:
            await self.runner.cleanup()
            self.logger.info("Phishing server stopped")

    async def _handle_track_open(self, request: web.Request) -> web.Response:
        """Track email open via tracking pixel."""
        campaign_id = request.match_info["campaign_id"]
        tracking_id = request.match_info["tracking_id"]

        campaign = self.campaign_manager.get_campaign(campaign_id)
        if campaign:
            target = campaign.get_target_by_tracking_id(tracking_id)
            if target and not target.email_opened:
                target.email_opened = True
                target.opened_at = datetime.now(timezone.utc)
                self.campaign_manager.save_campaign(campaign)
                self.logger.info(f"Email opened: {target.email} (campaign: {campaign.name})")

        # Return 1x1 transparent GIF
        gif = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
        return web.Response(body=gif, content_type="image/gif")

    async def _handle_pixel(self, request: web.Request) -> web.Response:
        """Handle tracking pixel request."""
        return await self._handle_track_open(request)

    async def _handle_click(self, request: web.Request) -> web.Response:
        """Track link click and redirect to landing page."""
        campaign_id = request.match_info["campaign_id"]
        tracking_id = request.match_info["tracking_id"]

        campaign = self.campaign_manager.get_campaign(campaign_id)
        if campaign:
            target = campaign.get_target_by_tracking_id(tracking_id)
            if target and not target.link_clicked:
                target.link_clicked = True
                target.clicked_at = datetime.now(timezone.utc)
                self.campaign_manager.save_campaign(campaign)
                self.logger.info(f"Link clicked: {target.email} (campaign: {campaign.name})")

                # Call click callbacks
                for callback in self._on_click_callbacks:
                    try:
                        callback(campaign, target)
                    except Exception as e:
                        self.logger.error(f"Click callback error: {e}")

        # Redirect to landing page
        raise web.HTTPFound(f"/landing/{campaign_id}/{tracking_id}")

    async def _handle_landing(self, request: web.Request) -> web.Response:
        """Serve the phishing landing page."""
        campaign_id = request.match_info["campaign_id"]
        tracking_id = request.match_info["tracking_id"]

        campaign = self.campaign_manager.get_campaign(campaign_id)
        if not campaign:
            return web.Response(text="Not found", status=404)

        template = self.template_manager.get_landing_template(campaign.landing_template_id)
        if not template:
            return web.Response(text="Template not found", status=404)

        # Render landing page
        html = template.html.format(
            tracking_id=tracking_id,
            capture_endpoint=f"/capture/{campaign_id}",
            tracking_pixel=f"/pixel/{campaign_id}/{tracking_id}.gif",
        )

        return web.Response(text=html, content_type="text/html")

    async def _handle_capture(self, request: web.Request) -> web.Response:
        """Handle credential capture (for awareness training)."""
        campaign_id = request.match_info["campaign_id"]

        campaign = self.campaign_manager.get_campaign(campaign_id)
        if not campaign:
            return web.Response(text="Not found", status=404)

        data = await request.post()
        tracking_id = data.get("tracking_id", "")

        target = campaign.get_target_by_tracking_id(tracking_id)
        if target and not target.credentials_submitted:
            target.credentials_submitted = True
            target.submitted_at = datetime.now(timezone.utc)
            self.campaign_manager.save_campaign(campaign)

            self.logger.warning(f"Credentials submitted: {target.email} (campaign: {campaign.name})")

            # Call submit callbacks
            for callback in self._on_submit_callbacks:
                try:
                    # Note: We don't pass actual credentials - just the event
                    callback(campaign, target, list(data.keys()))
                except Exception as e:
                    self.logger.error(f"Submit callback error: {e}")

        # Show awareness page
        awareness_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Awareness Training</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .alert { background: #fff3cd; border: 1px solid #ffc107; padding: 20px; border-radius: 5px; }
        h1 { color: #856404; }
    </style>
</head>
<body>
    <div class="alert">
        <h1>⚠️ This was a phishing simulation</h1>
        <p>This was a security awareness exercise conducted by your IT security team.</p>
        <p>You entered your credentials on a simulated phishing page. In a real attack,
        your credentials could have been stolen by attackers.</p>
        <h2>How to spot phishing:</h2>
        <ul>
            <li>Check the sender's email address carefully</li>
            <li>Look for spelling and grammar errors</li>
            <li>Hover over links before clicking to see the real URL</li>
            <li>Never enter credentials on unfamiliar pages</li>
            <li>When in doubt, contact IT directly</li>
        </ul>
        <p>If you have questions, please contact your IT security team.</p>
    </div>
</body>
</html>
        """

        return web.Response(text=awareness_html, content_type="text/html")
