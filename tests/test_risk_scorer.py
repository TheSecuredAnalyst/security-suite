"""Tests for vulnerability risk scoring."""

from modules.vulnscan.risk_scorer import (
    SEVERITY_COLOR,
    RiskScorer,
    calculate_risk_score,
)


class TestCalculateRiskScore:
    """Score and level derivation from CVE severity lists."""

    def test_empty_list_scores_zero_none(self):
        assert calculate_risk_score([]) == (0, "NONE")

    def test_single_critical_saturates_the_cap(self):
        # CRITICAL weight 10 * multiplier 10 = 100, capped at 100.
        score, level = calculate_risk_score([{"severity": "CRITICAL"}])
        assert score == 100
        assert level == "CRITICAL"

    def test_score_is_capped_at_100(self):
        score, _ = calculate_risk_score([{"severity": "CRITICAL"}] * 25)
        assert score == 100

    def test_single_high(self):
        assert calculate_risk_score([{"severity": "HIGH"}]) == (70, "HIGH")

    def test_single_medium(self):
        assert calculate_risk_score([{"severity": "MEDIUM"}]) == (40, "MEDIUM")

    def test_single_low(self):
        assert calculate_risk_score([{"severity": "LOW"}]) == (20, "LOW")

    def test_unknown_severity_uses_weight_one(self):
        assert calculate_risk_score([{"severity": "UNKNOWN"}]) == (10, "MINIMAL")

    def test_unrecognised_severity_falls_back_to_weight_one(self):
        assert calculate_risk_score([{"severity": "BOGUS"}]) == (10, "MINIMAL")

    def test_missing_severity_key_falls_back_to_weight_one(self):
        assert calculate_risk_score([{}]) == (10, "MINIMAL")

    def test_severities_accumulate(self):
        # LOW(2) + LOW(2) = 4 * 10 = 40 -> MEDIUM
        assert calculate_risk_score([{"severity": "LOW"}] * 2) == (40, "MEDIUM")

    def test_more_cves_never_lowers_the_score(self):
        """Absolute accumulation, not ratio-based averaging."""
        one = calculate_risk_score([{"severity": "MEDIUM"}])[0]
        many = calculate_risk_score(
            [{"severity": "MEDIUM"}] + [{"severity": "LOW"}] * 5
        )[0]
        assert many >= one

    def test_level_boundaries(self):
        """Each threshold maps to the documented band."""
        # 8 UNKNOWN (weight 1) = 80 -> CRITICAL
        assert calculate_risk_score([{"severity": "UNKNOWN"}] * 8)[1] == "CRITICAL"
        # 6 UNKNOWN = 60 -> HIGH
        assert calculate_risk_score([{"severity": "UNKNOWN"}] * 6)[1] == "HIGH"
        # 4 UNKNOWN = 40 -> MEDIUM
        assert calculate_risk_score([{"severity": "UNKNOWN"}] * 4)[1] == "MEDIUM"
        # 2 UNKNOWN = 20 -> LOW
        assert calculate_risk_score([{"severity": "UNKNOWN"}] * 2)[1] == "LOW"
        # 1 UNKNOWN = 10 -> MINIMAL
        assert calculate_risk_score([{"severity": "UNKNOWN"}])[1] == "MINIMAL"


class TestRiskScorer:
    """The stateless helper wrapper."""

    def test_score_delegates_to_calculate_risk_score(self):
        cves = [{"severity": "HIGH"}, {"severity": "LOW"}]
        assert RiskScorer.score(cves) == calculate_risk_score(cves)

    def test_color_known_level(self):
        assert RiskScorer.color("CRITICAL") == "bold red"

    def test_color_is_case_insensitive(self):
        assert RiskScorer.color("critical") == SEVERITY_COLOR["CRITICAL"]

    def test_color_unknown_level_defaults_to_white(self):
        assert RiskScorer.color("NOT_A_LEVEL") == "white"

    def test_every_documented_level_has_a_color(self):
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL", "NONE"):
            assert RiskScorer.color(level) != "white", f"{level} has no color"
