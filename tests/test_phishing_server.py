"""Tests for phishing-server request handling: id validation, escaping, redirects."""

from types import SimpleNamespace

import pytest
from aiohttp import web

from modules.phishing.server import PhishingServer, _is_valid_id

VALID_CAMPAIGN_ID = "3f2b1c8a-0e4d-4a1b-9c7e-5d6f7a8b9c0d"
VALID_TRACKING_ID = "a1b2c3d4"


class FakeRequest:
    """Minimal stand-in for web.Request — the handlers only read match_info."""

    def __init__(self, **match_info):
        self.match_info = match_info


def _server(landing_html: str = "<input value='{tracking_id}'>"):
    """Build a server whose managers return one campaign and one template."""
    target = SimpleNamespace(
        email="user@example.com",
        tracking_id=VALID_TRACKING_ID,
        email_opened=False,
        link_clicked=False,
        credentials_submitted=False,
        opened_at=None,
        clicked_at=None,
        submitted_at=None,
    )
    campaign = SimpleNamespace(
        id=VALID_CAMPAIGN_ID,
        name="Q3 Awareness",
        landing_template_id="office365",
        get_target_by_tracking_id=lambda tid: target if tid == VALID_TRACKING_ID else None,
    )
    campaign_manager = SimpleNamespace(
        get_campaign=lambda cid: campaign if cid == VALID_CAMPAIGN_ID else None,
        save_campaign=lambda _c: None,
    )
    template_manager = SimpleNamespace(
        get_landing_template=lambda _tid: SimpleNamespace(html=landing_html),
    )

    return PhishingServer(
        campaign_manager=campaign_manager, template_manager=template_manager
    )


class TestIdValidation:
    @pytest.mark.parametrize(
        "value",
        [VALID_CAMPAIGN_ID, VALID_TRACKING_ID, "a", "A1_b-2"],
    )
    def test_accepts_ids_we_issue(self, value):
        assert _is_valid_id(value)

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "..",
            "/etc/passwd",
            "//evil.example",
            "<script>alert(1)</script>",
            "id with space",
            "a" * 65,
            "id\nX",
        ],
    )
    def test_rejects_anything_else(self, value):
        assert not _is_valid_id(value)


class TestLandingPage:
    async def test_renders_for_a_known_campaign(self):
        response = await _server()._handle_landing(
            FakeRequest(campaign_id=VALID_CAMPAIGN_ID, tracking_id=VALID_TRACKING_ID)
        )
        assert response.status == 200
        assert VALID_TRACKING_ID in response.text

    async def test_malformed_tracking_id_is_404_not_reflected(self):
        payload = "<script>alert(1)</script>"
        response = await _server()._handle_landing(
            FakeRequest(campaign_id=VALID_CAMPAIGN_ID, tracking_id=payload)
        )
        assert response.status == 404
        assert payload not in response.text

    async def test_reflected_id_is_escaped_even_if_the_id_check_is_bypassed(
        self, monkeypatch
    ):
        """Defense in depth: the escaping must stand on its own."""
        from modules.phishing import server as server_module

        monkeypatch.setattr(server_module, "_is_valid_id", lambda _v: True)

        payload = '"><script>alert(1)</script>'
        server = _server()
        server.campaign_manager.get_campaign = lambda _cid: SimpleNamespace(
            id=VALID_CAMPAIGN_ID,
            name="Q3 Awareness",
            landing_template_id="office365",
            get_target_by_tracking_id=lambda _tid: None,
        )

        response = await server._handle_landing(
            FakeRequest(campaign_id=VALID_CAMPAIGN_ID, tracking_id=payload)
        )

        assert "<script>" not in response.text
        assert "&lt;script&gt;" in response.text

    async def test_unknown_campaign_is_404(self):
        response = await _server()._handle_landing(
            FakeRequest(campaign_id="ffffffff-0000-0000-0000-000000000000",
                        tracking_id=VALID_TRACKING_ID)
        )
        assert response.status == 404


class TestClickRedirect:
    async def test_redirects_to_a_local_landing_path(self):
        with pytest.raises(web.HTTPFound) as exc_info:
            await _server()._handle_click(
                FakeRequest(campaign_id=VALID_CAMPAIGN_ID, tracking_id=VALID_TRACKING_ID)
            )

        location = exc_info.value.location
        assert location == f"/landing/{VALID_CAMPAIGN_ID}/{VALID_TRACKING_ID}"

    @pytest.mark.parametrize(
        "campaign_id",
        ["//evil.example", "https://evil.example", "..%2f..%2fadmin"],
    )
    async def test_offsite_redirect_attempts_are_404(self, campaign_id):
        response = await _server()._handle_click(
            FakeRequest(campaign_id=campaign_id, tracking_id=VALID_TRACKING_ID)
        )
        assert response.status == 404


class TestTrackingPixel:
    async def test_valid_request_returns_gif(self):
        response = await _server()._handle_track_open(
            FakeRequest(campaign_id=VALID_CAMPAIGN_ID, tracking_id=VALID_TRACKING_ID)
        )
        assert response.content_type == "image/gif"

    async def test_malformed_id_is_404(self):
        response = await _server()._handle_track_open(
            FakeRequest(campaign_id="../../etc", tracking_id=VALID_TRACKING_ID)
        )
        assert response.status == 404
