"""Tests for Rules of Engagement scope validation."""

from modules.vulnscan.roe import RulesOfEngagement, _parse_networks


class TestParseNetworks:
    def test_parses_valid_cidrs(self):
        nets = _parse_networks(["10.0.0.0/8", "192.168.1.0/24"])
        assert len(nets) == 2

    def test_skips_invalid_cidrs_silently(self):
        nets = _parse_networks(["10.0.0.0/8", "not-a-cidr", "999.1.1.1/24"])
        assert len(nets) == 1

    def test_skips_blank_entries(self):
        assert _parse_networks(["", "   ", "10.0.0.0/8"]) != []
        assert len(_parse_networks(["", "   "])) == 0

    def test_handles_none(self):
        assert _parse_networks(None) == []

    def test_strips_whitespace(self):
        assert len(_parse_networks(["  10.0.0.0/8  "])) == 1

    def test_host_bits_set_are_tolerated(self):
        """strict=False, so 10.0.0.5/8 is accepted rather than raising."""
        assert len(_parse_networks(["10.0.0.5/8"])) == 1


class TestIsConfigured:
    def test_false_when_no_scopes(self):
        assert RulesOfEngagement().is_configured is False

    def test_true_with_allowed_scope(self):
        assert RulesOfEngagement(allowed_cidrs=["10.0.0.0/8"]).is_configured is True

    def test_true_with_forbidden_scope_only(self):
        assert RulesOfEngagement(forbidden_cidrs=["10.0.0.1/32"]).is_configured is True

    def test_false_when_all_scopes_are_invalid(self):
        assert RulesOfEngagement(allowed_cidrs=["garbage"]).is_configured is False


class TestEvaluateSingleIPs:
    def test_ip_inside_allowed_scope_produces_no_warning(self):
        roe = RulesOfEngagement(allowed_cidrs=["10.0.0.0/8"])
        warnings, allowed = roe.evaluate(["10.1.2.3"])
        assert warnings == []
        assert allowed == ["10.1.2.3"]

    def test_ip_outside_allowed_scope_warns(self):
        roe = RulesOfEngagement(allowed_cidrs=["10.0.0.0/8"])
        warnings, _ = roe.evaluate(["8.8.8.8"])
        assert len(warnings) == 1
        assert "outside the allowed scope" in warnings[0]

    def test_ip_in_forbidden_scope_warns(self):
        roe = RulesOfEngagement(
            allowed_cidrs=["192.168.1.0/24"],
            forbidden_cidrs=["192.168.1.1/32"],
        )
        warnings, _ = roe.evaluate(["192.168.1.1"])
        assert any("forbidden scope" in w for w in warnings)

    def test_forbidden_ip_still_appears_in_returned_targets(self):
        """evaluate() is advisory: it warns but does not filter.

        Callers must act on `warnings` — treating the second return value as a
        safe-to-scan list would scan a forbidden host.
        """
        roe = RulesOfEngagement(forbidden_cidrs=["192.168.1.1/32"])
        warnings, allowed = roe.evaluate(["192.168.1.1"])
        assert warnings
        assert allowed == ["192.168.1.1"]

    def test_no_allowed_scope_means_no_scope_warning(self):
        roe = RulesOfEngagement(forbidden_cidrs=["10.0.0.1/32"])
        warnings, _ = roe.evaluate(["8.8.8.8"])
        assert warnings == []


class TestEvaluateCIDRs:
    def test_cidr_within_allowed_scope_is_clean(self):
        roe = RulesOfEngagement(allowed_cidrs=["10.0.0.0/8"])
        warnings, _ = roe.evaluate(["10.1.0.0/16"])
        assert warnings == []

    def test_cidr_outside_allowed_scope_warns(self):
        roe = RulesOfEngagement(allowed_cidrs=["10.0.0.0/8"])
        warnings, _ = roe.evaluate(["172.16.0.0/16"])
        assert any("outside the allowed scope" in w for w in warnings)

    def test_cidr_overlapping_forbidden_scope_warns(self):
        roe = RulesOfEngagement(
            allowed_cidrs=["192.168.0.0/16"],
            forbidden_cidrs=["192.168.1.1/32"],
        )
        warnings, _ = roe.evaluate(["192.168.1.0/24"])
        assert any("overlaps forbidden scope" in w for w in warnings)

    def test_partial_overlap_with_allowed_scope_is_not_flagged(self):
        """overlaps() is permissive — any intersection satisfies the check."""
        roe = RulesOfEngagement(allowed_cidrs=["10.0.0.0/24"])
        warnings, _ = roe.evaluate(["10.0.0.0/16"])
        assert warnings == []


class TestEvaluateHostnames:
    def test_hostname_warns_that_validation_was_skipped(self):
        roe = RulesOfEngagement(allowed_cidrs=["10.0.0.0/8"])
        warnings, allowed = roe.evaluate(["example.com"])
        assert len(warnings) == 1
        assert "scope validation skipped" in warnings[0]
        assert allowed == ["example.com"]

    def test_hostname_is_not_blocked(self):
        roe = RulesOfEngagement(allowed_cidrs=["10.0.0.0/8"])
        _, allowed = roe.evaluate(["example.com"])
        assert allowed == ["example.com"]


class TestEvaluateMisc:
    def test_blank_targets_are_dropped(self):
        roe = RulesOfEngagement()
        warnings, allowed = roe.evaluate(["", "  ", "10.0.0.1"])
        assert allowed == ["10.0.0.1"]
        assert warnings == []

    def test_targets_are_stripped(self):
        roe = RulesOfEngagement(allowed_cidrs=["10.0.0.0/8"])
        _, allowed = roe.evaluate(["  10.0.0.1  "])
        assert allowed == ["10.0.0.1"]

    def test_multiple_targets_accumulate_warnings(self):
        roe = RulesOfEngagement(allowed_cidrs=["10.0.0.0/8"])
        warnings, allowed = roe.evaluate(["10.0.0.1", "8.8.8.8", "1.1.1.1"])
        assert len(warnings) == 2
        assert len(allowed) == 3

    def test_ipv6_target_is_handled(self):
        roe = RulesOfEngagement(allowed_cidrs=["2001:db8::/32"])
        warnings, _ = roe.evaluate(["2001:db8::1"])
        assert warnings == []

    def test_empty_target_list(self):
        assert RulesOfEngagement().evaluate([]) == ([], [])

    def test_non_string_targets_are_coerced(self):
        roe = RulesOfEngagement()
        _, allowed = roe.evaluate([12345])
        assert allowed == ["12345"]
