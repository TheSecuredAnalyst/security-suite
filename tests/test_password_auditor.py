"""Tests for the password strength auditor."""

import csv
import json

import pytest

from core.models import Target
from modules.password.auditor import (
    AuditResult,
    PasswordAuditor,
    PolicyMode,
    _charset_size,
    _entropy,
    _find_patterns,
    _risk_label,
    _score,
)


class TestCharsetSize:
    def test_lowercase_only(self):
        assert _charset_size("abcdef") == 26

    def test_uppercase_only(self):
        assert _charset_size("ABCDEF") == 26

    def test_digits_only(self):
        assert _charset_size("123456") == 10

    def test_specials_only(self):
        assert _charset_size("!@#$%^") == 32

    def test_mixed_charsets_accumulate(self):
        assert _charset_size("aA1!") == 26 + 26 + 10 + 32

    def test_empty_password_never_returns_zero(self):
        """Guards against log2(0) in the entropy calculation."""
        assert _charset_size("") == 1


class TestEntropy:
    def test_empty_password_has_zero_entropy(self):
        assert _entropy("") == 0.0

    def test_longer_password_has_more_entropy(self):
        assert _entropy("abcdefghij") > _entropy("abcde")

    def test_wider_charset_has_more_entropy(self):
        assert _entropy("aA1!aA1!") > _entropy("abcdefgh")

    def test_known_value(self):
        # 8 lowercase chars over a 26-char alphabet
        assert _entropy("abcdefgh") == pytest.approx(8 * 4.7004, rel=1e-3)


class TestFindPatterns:
    def test_repeated_characters(self):
        assert any("repeated" in p for p in _find_patterns("aaabbb"))

    def test_two_repeats_are_not_flagged(self):
        assert not any("repeated" in p for p in _find_patterns("aabxycz"))

    def test_sequential_letters(self):
        assert "sequential characters" in _find_patterns("abcxyz")

    def test_reverse_sequential_letters(self):
        assert "sequential characters" in _find_patterns("cbaxyz")

    def test_sequential_digits(self):
        assert "sequential characters" in _find_patterns("456xyz")

    def test_keyboard_run(self):
        assert any("keyboard pattern" in p for p in _find_patterns("Xqwerty!"))

    def test_all_numeric(self):
        assert "all numeric" in _find_patterns("98765432")

    def test_mixed_password_is_not_all_numeric(self):
        assert "all numeric" not in _find_patterns("abc123")

    def test_clean_password_has_no_patterns(self):
        assert _find_patterns("Tr0ub4dor&3xK") == []

    def test_sequence_check_spans_the_letter_digit_boundary(self):
        """Documented quirk: _SEQUENCES concatenates a-z and 0-9, so 'z01'
        reads as sequential even though it crosses character classes."""
        assert "sequential characters" in _find_patterns("z01qxm")

    def test_each_pattern_is_reported_once(self):
        found = _find_patterns("aaaqwerty123")
        assert len(found) == len(set(found))


class TestScore:
    def test_score_is_bounded(self):
        for pw in ("", "a", "password", "x" * 200, "Tr0ub4dor&3xK!Zq9"):
            score, _ = _score(pw, PolicyMode.ENTERPRISE)
            assert 0 <= score <= 100

    def test_preferred_length_beats_minimum_length(self):
        short = _score("Abcdfgh1jklm!x", PolicyMode.ENTERPRISE)[0]   # 14 chars
        long = _score("Abcdfgh1jklm!xqrstuv", PolicyMode.ENTERPRISE)[0]  # 20 chars
        assert long > short

    def test_too_short_is_penalised_and_explained(self):
        score, deductions = _score("Ab1!", PolicyMode.ENTERPRISE)
        assert any("too short" in d for d in deductions)
        assert score < 50

    def test_common_password_is_penalised(self):
        _, deductions = _score("password", PolicyMode.ENTERPRISE)
        assert any("common password" in d for d in deductions)

    def test_common_check_is_case_insensitive(self):
        _, deductions = _score("PASSWORD", PolicyMode.ENTERPRISE)
        assert any("common password" in d for d in deductions)

    def test_character_variety_increases_the_score(self):
        plain = _score("abcdefghijklmnop", PolicyMode.ENTERPRISE)[0]
        varied = _score("aBcdefgh1jklmno!", PolicyMode.ENTERPRISE)[0]
        assert varied > plain

    def test_patterns_are_penalised(self):
        clean = _score("Xk9mVq2wRt7bZp4d", PolicyMode.ENTERPRISE)[0]
        patterned = _score("Xk9mVqqq2wRt7bZp", PolicyMode.ENTERPRISE)[0]
        assert patterned < clean

    def test_home_policy_is_more_lenient_than_enterprise(self):
        pw = "Abcdfgh1jklm!"  # 13 chars: meets home min (12), under enterprise min (14)
        assert _score(pw, PolicyMode.HOME)[0] > _score(pw, PolicyMode.ENTERPRISE)[0]

    def test_empty_password_scores_zero(self):
        assert _score("", PolicyMode.ENTERPRISE)[0] == 0


class TestRiskLabel:
    @pytest.mark.parametrize("score,expected", [
        (100, "STRONG"), (80, "STRONG"),
        (79, "LOW"), (60, "LOW"),
        (59, "MEDIUM"), (40, "MEDIUM"),
        (39, "HIGH"), (20, "HIGH"),
        (19, "CRITICAL"), (0, "CRITICAL"),
    ])
    def test_boundaries(self, score, expected):
        assert _risk_label(score) == expected


class TestAudit:
    def test_empty_password_is_critical(self):
        result = PasswordAuditor().audit("")
        assert result.score == 0
        assert result.risk_label == "CRITICAL"
        assert result.length == 0
        assert result.recommendations == ["Password cannot be empty"]

    def test_strong_password(self):
        result = PasswordAuditor(PolicyMode.ENTERPRISE).audit("Xk9mVq2wRt7bZp4dLn6!")
        assert result.risk_label == "STRONG"
        assert result.patterns_found == []

    def test_common_password_is_flagged(self):
        result = PasswordAuditor().audit("password")
        assert result.is_common is True
        assert result.risk_label in ("CRITICAL", "HIGH")

    def test_character_class_flags(self):
        result = PasswordAuditor().audit("Abc123!x")
        assert (result.has_upper, result.has_lower, result.has_digit, result.has_special) == (
            True, True, True, True,
        )

    def test_missing_character_classes_are_reported(self):
        result = PasswordAuditor().audit("abcdefghijklmnop")
        assert result.has_upper is False
        assert result.has_digit is False
        assert result.has_special is False

    def test_length_and_entropy_are_recorded(self):
        result = PasswordAuditor().audit("abcdefgh")
        assert result.length == 8
        assert result.entropy == pytest.approx(37.6, abs=0.1)

    def test_entropy_is_rounded_to_two_places(self):
        result = PasswordAuditor().audit("Xk9mVq2w")
        assert result.entropy == round(result.entropy, 2)

    def test_result_never_contains_the_plaintext(self):
        """Privacy guarantee: metrics only, never the password itself."""
        secret = "SuperSecret123!"
        payload = json.dumps(PasswordAuditor().audit(secret).to_dict())
        assert secret not in payload

    def test_policy_affects_the_outcome(self):
        pw = "Abcdfgh1jklm!"
        assert (
            PasswordAuditor(PolicyMode.HOME).audit(pw).score
            > PasswordAuditor(PolicyMode.ENTERPRISE).audit(pw).score
        )

    def test_default_policy_is_enterprise(self):
        assert PasswordAuditor().policy == PolicyMode.ENTERPRISE


class TestRecommendations:
    def test_short_password_is_told_to_grow(self):
        recs = PasswordAuditor().audit("Ab1!").recommendations
        assert any("Increase length" in r for r in recs)

    def test_missing_uppercase(self):
        assert any("uppercase" in r for r in PasswordAuditor().audit("abc123!x").recommendations)

    def test_missing_lowercase(self):
        assert any("lowercase" in r for r in PasswordAuditor().audit("ABC123!X").recommendations)

    def test_missing_digits(self):
        assert any("numbers" in r for r in PasswordAuditor().audit("Abcdefgh!x").recommendations)

    def test_missing_specials(self):
        assert any("special" in r for r in PasswordAuditor().audit("Abcdefgh1x").recommendations)

    def test_common_password_advice(self):
        assert any(
            "password manager" in r for r in PasswordAuditor().audit("password").recommendations
        )

    def test_pattern_advice(self):
        assert any(
            "predictable patterns" in r
            for r in PasswordAuditor().audit("Xk9mVqqq2wRt7bZp").recommendations
        )

    def test_compliant_password_gets_a_pass_message(self):
        recs = PasswordAuditor(PolicyMode.ENTERPRISE).audit("Xk9mVq2wRt7bZp4dLn6!").recommendations
        assert recs == ["Password meets policy requirements"]


class TestAuditFile:
    def test_audits_each_line(self, tmp_path):
        f = tmp_path / "pw.txt"
        f.write_text("password\nXk9mVq2wRt7bZp4dLn6!\nabc123\n")
        assert len(PasswordAuditor().audit_file(str(f))) == 3

    def test_skips_blank_lines_and_comments(self, tmp_path):
        f = tmp_path / "pw.txt"
        f.write_text("# a comment\n\npassword\n\n# another\nabc123\n")
        assert len(PasswordAuditor().audit_file(str(f))) == 2

    def test_missing_file_returns_empty_list(self, tmp_path):
        assert PasswordAuditor().audit_file(str(tmp_path / "nope.txt")) == []

    def test_empty_file_returns_empty_list(self, tmp_path):
        f = tmp_path / "pw.txt"
        f.write_text("")
        assert PasswordAuditor().audit_file(str(f)) == []

    def test_preserves_trailing_whitespace_in_passwords(self, tmp_path):
        f = tmp_path / "pw.txt"
        f.write_text("abc  \n")
        assert PasswordAuditor().audit_file(str(f))[0].length == 5


class TestExports:
    @pytest.fixture
    def results(self):
        auditor = PasswordAuditor()
        return [auditor.audit("password"), auditor.audit("Xk9mVq2wRt7bZp4dLn6!")]

    def test_export_json_writes_all_records(self, results, tmp_path):
        out = tmp_path / "out.json"
        assert PasswordAuditor().export_json(results, str(out)) == str(out)
        assert len(json.loads(out.read_text())) == 2

    def test_export_json_creates_missing_directories(self, results, tmp_path):
        out = tmp_path / "nested" / "deep" / "out.json"
        PasswordAuditor().export_json(results, str(out))
        assert out.exists()

    def test_export_json_omits_plaintext(self, tmp_path):
        secret = "Zq7wXm4vTn9!Kb2r"
        out = tmp_path / "out.json"
        PasswordAuditor().export_json([PasswordAuditor().audit(secret)], str(out))
        assert secret not in out.read_text()

    def test_export_csv_writes_header_and_rows(self, results, tmp_path):
        out = tmp_path / "out.csv"
        PasswordAuditor().export_csv(results, str(out))
        rows = list(csv.DictReader(out.read_text().splitlines()))
        assert len(rows) == 2
        assert "score" in rows[0]

    def test_export_csv_creates_missing_directories(self, results, tmp_path):
        out = tmp_path / "nested" / "out.csv"
        PasswordAuditor().export_csv(results, str(out))
        assert out.exists()

    def test_export_csv_with_no_results_writes_nothing(self, tmp_path):
        out = tmp_path / "out.csv"
        assert PasswordAuditor().export_csv([], str(out)) == str(out)
        assert not out.exists()

    def test_export_json_with_no_results_writes_empty_array(self, tmp_path):
        out = tmp_path / "out.json"
        PasswordAuditor().export_json([], str(out))
        assert json.loads(out.read_text()) == []


class TestAuditResultModel:
    def test_to_dict_contains_all_metric_fields(self):
        d = PasswordAuditor().audit("Abc123!x").to_dict()
        assert set(d) == {
            "length", "entropy", "score", "risk_label", "has_upper", "has_lower",
            "has_digit", "has_special", "is_common", "patterns_found", "recommendations",
        }

    def test_list_fields_default_to_empty(self):
        result = AuditResult(
            length=1, entropy=0.0, score=0, risk_label="CRITICAL",
            has_upper=False, has_lower=False, has_digit=False, has_special=False,
            is_common=False,
        )
        assert result.patterns_found == []
        assert result.recommendations == []


class TestRunInterface:
    async def test_run_returns_an_informational_scan_result(self):
        target = Target(value="label", target_type="username")
        result = await PasswordAuditor().run(target)
        assert result.module == "password.auditor"
        assert len(result.findings) == 1

    async def test_run_does_not_leak_a_password_into_the_finding(self):
        target = Target(value="label", target_type="username")
        result = await PasswordAuditor().run(target)
        assert "label" not in result.findings[0].description
