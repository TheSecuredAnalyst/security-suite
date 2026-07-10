"""Tests for the secure password/passphrase generator.

The generator's whole value is that it produces strong, well-formed secrets, so
the tests assert the invariants (length, composition, uniqueness) rather than
exact output.
"""

import string

import pytest

from modules.password.generator import PasswordGenerator


def test_default_length_and_composition():
    pw = PasswordGenerator.generate()
    assert len(pw) == 20
    assert any(c.isupper() for c in pw)
    assert any(c.islower() for c in pw)
    assert any(c.isdigit() for c in pw)
    assert any(not c.isalnum() for c in pw)


def test_custom_length_respected():
    assert len(PasswordGenerator.generate(length=32)) == 32


def test_short_length_rejected():
    with pytest.raises(ValueError, match="at least 8"):
        PasswordGenerator.generate(length=4)


def test_no_character_class_rejected():
    with pytest.raises(ValueError, match="character class"):
        PasswordGenerator.generate(
            use_upper=False, use_lower=False, use_digits=False, use_special=False
        )


def test_exclude_ambiguous_removes_lookalikes():
    pw = PasswordGenerator.generate(
        length=200, use_special=False, exclude_ambiguous=True
    )
    assert not (set(pw) & set("O0Il1"))


def test_digits_only_pool():
    pw = PasswordGenerator.generate(
        length=16, use_upper=False, use_lower=False, use_special=False
    )
    assert all(c in string.digits for c in pw)


def test_generate_many_are_unique():
    pws = PasswordGenerator.generate_many(count=25, length=24)
    assert len(pws) == 25
    assert len(set(pws)) == 25


def test_passphrase_word_count_and_separator():
    phrase = PasswordGenerator.generate_passphrase(
        word_count=4, separator="-", append_number=False, append_special=False
    )
    assert phrase.count("-") == 3
    assert all(part.isalpha() for part in phrase.split("-"))


def test_passphrase_minimum_three_words():
    phrase = PasswordGenerator.generate_passphrase(
        word_count=1, append_number=False, append_special=False
    )
    assert phrase.count("-") == 2  # clamped up to 3 words


def test_passphrase_appends_number_and_special():
    phrase = PasswordGenerator.generate_passphrase(
        word_count=3, append_number=True, append_special=True
    )
    assert phrase[-1] in "!@#$%&*"
    assert any(c.isdigit() for c in phrase)
