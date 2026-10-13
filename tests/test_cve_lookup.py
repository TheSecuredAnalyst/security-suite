"""Tests for NVD-backed CVE enrichment.

The NVD HTTP calls (_nvd_query) are mocked throughout — no test hits the
network. Focus is the parsing/filtering helpers and the multi-step lookup
strategy in CVELookup.lookup.
"""

from unittest.mock import AsyncMock, patch

import pytest

from modules.vulnscan.cve_lookup import (
    CVELookup,
    _cve_year,
    _dedup,
    _extract_cvss,
    _normalise_version,
    _parse_vulns,
    calculate_risk_score,
)


def _vuln(cve_id, score=9.0, severity="CRITICAL", desc="a vuln", metric="cvssMetricV31"):
    """Build a raw NVD vulnerability item."""
    return {
        "cve": {
            "id": cve_id,
            "metrics": {
                metric: [{"cvssData": {"baseScore": score, "baseSeverity": severity}}],
            },
            "descriptions": [{"lang": "en", "value": desc}],
        }
    }


class TestExtractCVSS:
    def test_v31_is_preferred(self):
        metrics = {
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}],
        }
        assert _extract_cvss(metrics) == (9.8, "CRITICAL")

    def test_falls_back_to_v30(self):
        metrics = {"cvssMetricV30": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}
        assert _extract_cvss(metrics) == (7.5, "HIGH")

    def test_falls_back_to_v2(self):
        metrics = {"cvssMetricV2": [{"cvssData": {"baseScore": 4.3, "baseSeverity": "MEDIUM"}}]}
        assert _extract_cvss(metrics) == (4.3, "MEDIUM")

    def test_no_metrics_returns_unknown(self):
        assert _extract_cvss({}) == (0.0, "UNKNOWN")

    def test_severity_is_derived_when_missing(self):
        metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": 9.5}}]}
        assert _extract_cvss(metrics) == (9.5, "CRITICAL")

    def test_derived_severity_bands(self):
        def sev(score):
            return _extract_cvss({"cvssMetricV31": [{"cvssData": {"baseScore": score}}]})[1]
        assert sev(9.0) == "CRITICAL"
        assert sev(7.0) == "HIGH"
        assert sev(4.0) == "MEDIUM"
        assert sev(3.9) == "LOW"

    def test_severity_is_uppercased(self):
        metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": 7.0, "baseSeverity": "high"}}]}
        assert _extract_cvss(metrics)[1] == "HIGH"

    def test_missing_base_score_skips_to_unknown(self):
        metrics = {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]}
        assert _extract_cvss(metrics) == (0.0, "UNKNOWN")


class TestCVEYear:
    def test_valid(self):
        assert _cve_year("CVE-2021-44228") == 2021

    def test_malformed_returns_zero(self):
        assert _cve_year("not-a-cve") == 0

    def test_non_numeric_year_returns_zero(self):
        assert _cve_year("CVE-YYYY-1234") == 0

    def test_empty_returns_zero(self):
        assert _cve_year("") == 0


class TestNormaliseVersion:
    def test_strips_patch_suffix(self):
        assert _normalise_version("8.4p1") == "8.4"

    def test_strips_beta_suffix(self):
        assert _normalise_version("3.6.2b1") == "3.6.2"

    def test_all_numeric_returns_empty(self):
        # Already normalised — returns "" so the caller skips a duplicate query.
        assert _normalise_version("1.24.0") == ""

    def test_no_leading_digits_returns_original(self):
        assert _normalise_version("abc") == "abc"

    def test_single_number(self):
        assert _normalise_version("8") == ""


class TestParseVulns:
    def test_applies_cvss_floor(self):
        vulns = [_vuln("CVE-2020-1", score=3.0), _vuln("CVE-2020-2", score=8.0)]
        parsed = _parse_vulns(vulns, min_cvss=4.0)
        assert [c["id"] for c in parsed] == ["CVE-2020-2"]

    def test_applies_year_floor(self):
        vulns = [_vuln("CVE-2010-1", score=9.0), _vuln("CVE-2020-1", score=9.0)]
        parsed = _parse_vulns(vulns, min_year=2015)
        assert [c["id"] for c in parsed] == ["CVE-2020-1"]

    def test_respects_max_results(self):
        vulns = [_vuln(f"CVE-2020-{i}", score=9.0) for i in range(10)]
        assert len(_parse_vulns(vulns, max_results=3)) == 3

    def test_skips_items_without_an_id(self):
        vulns = [{"cve": {"metrics": {}}}, _vuln("CVE-2020-1")]
        assert [c["id"] for c in _parse_vulns(vulns)] == ["CVE-2020-1"]

    def test_long_description_is_truncated(self):
        vulns = [_vuln("CVE-2020-1", desc="x" * 500)]
        desc = _parse_vulns(vulns)[0]["description"]
        assert desc.endswith("...")
        assert len(desc) <= 303

    def test_result_shape(self):
        parsed = _parse_vulns([_vuln("CVE-2020-1", score=9.8, severity="CRITICAL")])
        assert set(parsed[0]) == {"id", "cvss_score", "severity", "description"}

    def test_empty_input(self):
        assert _parse_vulns([]) == []


class TestDedup:
    def test_keeps_highest_cvss_on_collision(self):
        cves = [
            {"id": "CVE-1", "cvss_score": 5.0},
            {"id": "CVE-1", "cvss_score": 9.0},
            {"id": "CVE-2", "cvss_score": 7.0},
        ]
        result = {c["id"]: c["cvss_score"] for c in _dedup(cves)}
        assert result == {"CVE-1": 9.0, "CVE-2": 7.0}

    def test_no_duplicates_passthrough(self):
        cves = [{"id": "CVE-1", "cvss_score": 5.0}]
        assert _dedup(cves) == cves

    def test_empty(self):
        assert _dedup([]) == []


class TestCalculateRiskScore:
    def test_empty(self):
        assert calculate_risk_score([]) == (0, "NONE")

    def test_accumulates_absolute_weights(self):
        assert calculate_risk_score([{"severity": "CRITICAL"}]) == (100, "CRITICAL")

    def test_unknown_severity_weight_one(self):
        assert calculate_risk_score([{"severity": "FOO"}]) == (10, "MINIMAL")

    def test_level_bands(self):
        assert calculate_risk_score([{"severity": "UNKNOWN"}] * 6)[1] == "HIGH"
        assert calculate_risk_score([{"severity": "UNKNOWN"}] * 4)[1] == "MEDIUM"


class TestLookup:
    @pytest.fixture
    def lookup(self):
        return CVELookup(max_results=5)

    async def test_empty_product_and_service_returns_empty(self, lookup):
        assert await lookup.lookup("", "", "") == []

    async def test_noisy_service_name_is_suppressed(self, lookup):
        with patch("modules.vulnscan.cve_lookup._nvd_query") as q:
            result = await lookup.lookup("http", "1.0")
        assert result == []
        q.assert_not_called()

    async def test_noise_check_is_case_insensitive(self, lookup):
        with patch("modules.vulnscan.cve_lookup._nvd_query") as q:
            assert await lookup.lookup("SSH", "8.4") == []
        q.assert_not_called()

    async def test_product_version_hit_returns_sorted(self, lookup):
        raw = [_vuln("CVE-2020-1", score=7.0, desc="CustomApp before 3.0 has a flaw"),
               _vuln("CVE-2021-2", score=9.5, desc="CustomApp remote code execution")]
        with patch("modules.vulnscan.cve_lookup._nvd_query",
                   AsyncMock(return_value=raw)) as q:
            result = await lookup.lookup("CustomApp", "2.0")
        assert [c["id"] for c in result] == ["CVE-2021-2", "CVE-2020-1"]
        q.assert_awaited_once()  # step 1 satisfied, no fallback

    async def test_falls_back_to_normalised_version(self, lookup):
        # Step 1 (raw "OpenApp 8.4p1") returns nothing; 1b ("OpenApp 8.4") hits.
        responses = [[], [_vuln("CVE-2021-9", score=8.0, desc="OpenApp 8.4 buffer overflow")]]
        with patch("modules.vulnscan.cve_lookup._nvd_query",
                   AsyncMock(side_effect=responses)) as q:
            result = await lookup.lookup("OpenApp", "8.4p1")
        assert [c["id"] for c in result] == ["CVE-2021-9"]
        assert q.await_count == 2

    async def test_dual_product_only_lookup_merges_and_dedups(self, lookup):
        # No version → skip step 1; step 2 fires two concurrent queries.
        crit = [_vuln("CVE-2021-1", score=9.8, desc="BespokeServer auth bypass")]
        recent = [_vuln("CVE-2021-1", score=9.8, desc="BespokeServer auth bypass"),
                  _vuln("CVE-2021-2", score=8.0, desc="BespokeServer path traversal")]
        with patch("modules.vulnscan.cve_lookup._nvd_query",
                   AsyncMock(side_effect=[crit, recent])):
            result = await lookup.lookup("BespokeServer")
        ids = [c["id"] for c in result]
        assert ids == ["CVE-2021-1", "CVE-2021-2"]  # deduped, sorted desc

    async def test_short_fallback_term_returns_empty(self, lookup):
        # Product <= 3 chars and no version → no product-only query.
        with patch("modules.vulnscan.cve_lookup._nvd_query",
                   AsyncMock(return_value=[])) as q:
            result = await lookup.lookup("abc")
        assert result == []
        q.assert_not_called()

    async def test_product_only_below_cvss_floor_returns_empty(self, lookup):
        # Step 2 uses a 7.0 floor; a 5.0 CVE is dropped.
        with patch("modules.vulnscan.cve_lookup._nvd_query",
                   AsyncMock(side_effect=[[_vuln("CVE-2021-1", score=5.0, desc="BespokeServer flaw")], []])):
            assert await lookup.lookup("BespokeServer") == []

    async def test_service_name_used_when_product_absent(self, lookup):
        with patch("modules.vulnscan.cve_lookup._nvd_query",
                   AsyncMock(side_effect=[[_vuln("CVE-2021-1", score=9.0, desc="BespokeServer flaw")], []])):
            result = await lookup.lookup("", "", service_name="BespokeServer")
        assert [c["id"] for c in result] == ["CVE-2021-1"]

    def test_sort_orders_by_cvss_descending(self):
        cves = [{"cvss_score": 3.0}, {"cvss_score": 9.0}, {"cvss_score": 5.0}]
        assert [c["cvss_score"] for c in CVELookup._sort(cves)] == [9.0, 5.0, 3.0]


# ── CPE applicability filter (the fix for keyword false matches) ─────────────
from modules.vulnscan.cve_lookup import _ver_key, cpe_applies  # noqa: E402


def _cve_with_cpes(cve_id, matches):
    """NVD item carrying a configurations/cpeMatch list, as NVD returns."""
    return {"cve": {"id": cve_id,
                    "configurations": [{"nodes": [{"cpeMatch": matches}]}]}}


def _m(criteria, **bounds):
    return {"criteria": criteria, "vulnerable": True, **bounds}


class TestVerKey:
    def test_patch_suffix_sorts_after_base(self):
        assert _ver_key("9.6p1") > _ver_key("9.6")
        assert _ver_key("9.6p1") < _ver_key("9.7")

    def test_ignores_distro_suffix(self):
        assert _ver_key("9.6p1 Ubuntu 3ubuntu13.19") == _ver_key("9.6p1")

    def test_no_number_is_none(self):
        assert _ver_key("") is None and _ver_key("latest") is None


class TestCpeApplies:
    # Real shape: CVE-2016-0746 affects nginx 0.6.18–1.8.0 and 1.9.0–<1.9.10.
    NGINX_0746 = [
        _m("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", versionStartIncluding="0.6.18", versionEndIncluding="1.8.0"),
        _m("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", versionStartIncluding="1.9.0", versionEndExcluding="1.9.10"),
    ]

    def test_modern_nginx_is_not_in_old_affected_range(self):
        applies, reason = cpe_applies(_cve_with_cpes("CVE-2016-0746", self.NGINX_0746)["cve"], "nginx", "1.24.0")
        assert applies is False and reason == "version-not-in-affected-range"

    def test_old_nginx_is_in_range(self):
        applies, _ = cpe_applies(_cve_with_cpes("CVE-2016-0746", self.NGINX_0746)["cve"], "nginx", "1.7.0")
        assert applies is True

    def test_different_product_is_dropped(self):
        # An Authelia CVE whose text mentions nginx, but whose CPE is authelia.
        cpes = [_m("cpe:2.3:a:authelia:authelia:*:*:*:*:*:*:*:*", versionEndExcluding="4.29.0")]
        applies, reason = cpe_applies(_cve_with_cpes("CVE-2021-32637", cpes)["cve"], "nginx", "1.24.0")
        assert applies is False and reason == "different-product"

    def test_pulpcore_cve_dropped_for_gunicorn(self):
        cpes = [_m("cpe:2.3:a:redhat:pulpcore:*:*:*:*:*:*:*:*", versionEndExcluding="3.22.0")]
        applies, reason = cpe_applies(_cve_with_cpes("CVE-2024-7923", cpes)["cve"], "Gunicorn", "")
        assert applies is False and reason == "different-product"

    def test_openssh_9_6p1_not_in_before_9_6(self):
        cpes = [_m("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", versionEndExcluding="9.6")]
        applies, reason = cpe_applies(_cve_with_cpes("CVE-2023-51385", cpes)["cve"], "OpenSSH", "9.6p1 Ubuntu 3ubuntu13.19")
        assert applies is False and reason == "version-not-in-affected-range"

    def test_product_match_unknown_version_is_kept(self):
        cpes = [_m("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", versionEndExcluding="1.99")]
        applies, reason = cpe_applies(_cve_with_cpes("CVE-X", cpes)["cve"], "nginx", "")
        assert applies is True and reason == "product-match-version-unknown"

    def test_no_cpe_and_no_description_match_is_dropped(self):
        # No CPE and nothing naming the product: cannot confirm it applies.
        applies, reason = cpe_applies({"id": "CVE-Y", "descriptions": []}, "nginx", "1.24.0")
        assert applies is False and reason == "no-cpe-desc-mismatch"

    def test_pinned_exact_version(self):
        cpes = [_m("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*")]
        assert cpe_applies(_cve_with_cpes("CVE-Z", cpes)["cve"], "nginx", "1.24.0")[0] is True
        assert cpe_applies(_cve_with_cpes("CVE-Z", cpes)["cve"], "nginx", "1.25.0")[0] is False


def test_parse_vulns_filters_by_cpe():
    """A keyword-matched CVE for another product is dropped once product is known."""
    authelia = {"cve": {"id": "CVE-2021-32637", "metrics": {
        "cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
        "descriptions": [{"lang": "en", "value": "Authelia ... nginx ngx_http_auth_request_module"}],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:authelia:authelia:*:*:*:*:*:*:*:*", "vulnerable": True, "versionEndExcluding": "4.29.0"}]}]}]}}
    assert _parse_vulns([authelia], product="nginx", version="1.24.0") == []
    assert len(_parse_vulns([authelia])) == 1  # no product given → old behaviour, kept


def _cve_no_cpe(cve_id, desc):
    return {"id": cve_id, "descriptions": [{"lang": "en", "value": desc}]}


class TestNoCpeFallback:
    """Recent CVEs often lack CPE data; fall back to the description subject."""

    def test_keeps_real_recent_openssh_cve(self):
        cve = _cve_no_cpe("CVE-2026-60002", "ssh in OpenSSH before 10.4 can have a logic error")
        assert cpe_applies(cve, "OpenSSH", "9.6p1")[0] is True

    def test_keeps_real_recent_nginx_cve(self):
        cve = _cve_no_cpe("CVE-2026-42055", "NGINX Plus and NGINX Open Source have a vulnerability")
        assert cpe_applies(cve, "nginx", "1.24.0")[0] is True

    @pytest.mark.parametrize("product,desc", [
        ("OpenSSH", "Kopia is a cross-platform backup tool for Windows, macOS, and Linux"),
        ("OpenSSH", "Apache MINA SSHD is a Java library for client-side and server-side SSH"),
        ("nginx", "The Divi Form Builder plugin for WordPress is vulnerable to arbitrary file upload"),
        ("nginx", "Laravel-Mediable before 7.0.0 contains a file handling vulnerability"),
        ("Gunicorn", "Incorrect access control in the setUPnPCfg function of a router"),
    ])
    def test_drops_unrelated_recent_cves(self, product, desc):
        applies, reason = cpe_applies(_cve_no_cpe("CVE-X", desc), product, "")
        assert applies is False and reason == "no-cpe-desc-mismatch"
