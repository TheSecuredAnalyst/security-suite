"""Tests for log-value scrubbing (CWE-117)."""

from core.logger import scrub


class TestScrub:
    def test_plain_value_is_unchanged(self):
        assert scrub("example.com") == "example.com"

    def test_non_string_values_are_coerced(self):
        assert scrub(443) == "443"

    def test_forged_log_line_is_flattened(self):
        forged = "10.0.0.5\nERROR    Firewall disabled by admin"
        scrubbed = scrub(forged)
        assert "\n" not in scrubbed
        assert scrubbed == "10.0.0.5 ERROR    Firewall disabled by admin"

    def test_carriage_returns_are_flattened(self):
        assert "\r" not in scrub("a\r\nb\rc")
        assert scrub("a\r\nb\rc") == "a b c"

    def test_control_and_escape_characters_are_removed(self):
        # ANSI escapes would otherwise let a target repaint an operator's console.
        assert scrub("host\x1b[31mred\x07") == "host[31mred"

    def test_long_values_are_truncated(self):
        scrubbed = scrub("A" * 400, max_length=100)
        assert len(scrubbed) == 101  # 100 chars + the ellipsis marker
        assert scrubbed.endswith("…")
