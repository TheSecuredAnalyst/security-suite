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
        raw = [_vuln("CVE-2020-1", score=7.0), _vuln("CVE-2021-2", score=9.5)]
        with patch("modules.vulnscan.cve_lookup._nvd_query",
                   AsyncMock(return_value=raw)) as q:
            result = await lookup.lookup("CustomApp", "2.0")
        assert [c["id"] for c in result] == ["CVE-2021-2", "CVE-2020-1"]
        q.assert_awaited_once()  # step 1 satisfied, no fallback

    async def test_falls_back_to_normalised_version(self, lookup):
        # Step 1 (raw "OpenApp 8.4p1") returns nothing; 1b ("OpenApp 8.4") hits.
        responses = [[], [_vuln("CVE-2021-9", score=8.0)]]
        with patch("modules.vulnscan.cve_lookup._nvd_query",
                   AsyncMock(side_effect=responses)) as q:
            result = await lookup.lookup("OpenApp", "8.4p1")
        assert [c["id"] for c in result] == ["CVE-2021-9"]
        assert q.await_count == 2

    async def test_dual_product_only_lookup_merges_and_dedups(self, lookup):
        # No version → skip step 1; step 2 fires two concurrent queries.
        crit = [_vuln("CVE-2021-1", score=9.8)]
        recent = [_vuln("CVE-2021-1", score=9.8), _vuln("CVE-2021-2", score=8.0)]
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
                   AsyncMock(side_effect=[[_vuln("CVE-2021-1", score=5.0)], []])):
            assert await lookup.lookup("BespokeServer") == []

    async def test_service_name_used_when_product_absent(self, lookup):
        with patch("modules.vulnscan.cve_lookup._nvd_query",
                   AsyncMock(side_effect=[[_vuln("CVE-2021-1", score=9.0)], []])):
            result = await lookup.lookup("", "", service_name="BespokeServer")
        assert [c["id"] for c in result] == ["CVE-2021-1"]

    def test_sort_orders_by_cvss_descending(self):
        cves = [{"cvss_score": 3.0}, {"cvss_score": 9.0}, {"cvss_score": 5.0}]
        assert [c["cvss_score"] for c in CVELookup._sort(cves)] == [9.0, 5.0, 3.0]
