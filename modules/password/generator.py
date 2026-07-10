"""
Secure password and passphrase generator — ported from password_security_suite_v2.
"""

from __future__ import annotations

import secrets
import string

from core.logger import get_logger

logger = get_logger("password.generator")

_WORD_LIST = [
    "alpine", "bridge", "castle", "desert", "ember", "forest", "glacier",
    "harbor", "island", "jungle", "kettle", "lantern", "mosaic", "nebula",
    "orbit", "prism", "quarry", "riddle", "silver", "temple", "umbra",
    "valley", "willow", "xenon", "yellow", "zenith", "anchor", "barrel",
    "candle", "dagger", "eclipse", "falcon", "goblin", "hammer", "igloo",
    "jester", "kipper", "locket", "mango", "noodle", "oyster", "pepper",
    "quartz", "rocket", "saddle", "tundra", "upland", "velvet", "walnut",
    "xyster", "yonder", "zipper",
]

_AMBIGUOUS = set("O0Il1")  # Chars that look alike — excluded in safe mode


class PasswordGenerator:
    """
    Cryptographically secure password and passphrase generator.

    All randomness uses secrets.choice / secrets.randbelow —
    never the random module.
    """

    @staticmethod
    def generate(
        length: int = 20,
        use_upper: bool = True,
        use_lower: bool = True,
        use_digits: bool = True,
        use_special: bool = True,
        exclude_ambiguous: bool = False,
        special_chars: str = "!@#$%^&*()-_=+[]{}|;:,.<>?",
    ) -> str:
        """
        Generate a cryptographically random password.

        Args:
            length: Total character count (default 20)
            use_upper: Include uppercase A-Z
            use_lower: Include lowercase a-z
            use_digits: Include digits 0-9
            use_special: Include special characters
            exclude_ambiguous: Remove O,0,I,l,1 lookalikes
            special_chars: Allowed special characters

        Returns:
            A random password string
        """
        if length < 8:
            raise ValueError("Password length must be at least 8")

        pool = ""
        mandatory: list[str] = []

        if use_upper:
            chars = string.ascii_uppercase
            if exclude_ambiguous:
                chars = "".join(c for c in chars if c not in _AMBIGUOUS)
            pool += chars
            mandatory.append(secrets.choice(chars))

        if use_lower:
            chars = string.ascii_lowercase
            if exclude_ambiguous:
                chars = "".join(c for c in chars if c not in _AMBIGUOUS)
            pool += chars
            mandatory.append(secrets.choice(chars))

        if use_digits:
            chars = string.digits
            if exclude_ambiguous:
                chars = "".join(c for c in chars if c not in _AMBIGUOUS)
            pool += chars
            mandatory.append(secrets.choice(chars))

        if use_special:
            pool += special_chars
            mandatory.append(secrets.choice(special_chars))

        if not pool:
            raise ValueError("At least one character class must be enabled")

        remaining = [secrets.choice(pool) for _ in range(length - len(mandatory))]
        password_chars = mandatory + remaining

        # Cryptographically shuffle (Fisher-Yates via secrets)
        for i in range(len(password_chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

        return "".join(password_chars)

    @staticmethod
    def generate_passphrase(
        word_count: int = 5,
        separator: str = "-",
        capitalize: bool = True,
        append_number: bool = True,
        append_special: bool = True,
    ) -> str:
        """
        Generate a memorable passphrase from a word list.

        Example output (5 words): Alpine-Bridge-Castle-Desert-Ember-42!

        Args:
            word_count: Number of words (default 5, minimum 3)
            separator: Character between words
            capitalize: Capitalize each word
            append_number: Append a 2-digit random number
            append_special: Append a random special character
        """
        word_count = max(3, word_count)
        words = [secrets.choice(_WORD_LIST) for _ in range(word_count)]
        if capitalize:
            words = [w.capitalize() for w in words]

        phrase = separator.join(words)

        if append_number:
            phrase += f"{secrets.randbelow(90) + 10}"  # 10–99

        if append_special:
            phrase += secrets.choice("!@#$%&*")

        return phrase

    @staticmethod
    def generate_many(count: int = 5, **kwargs) -> list[str]:
        """Generate multiple unique passwords."""
        passwords = set()
        while len(passwords) < count:
            passwords.add(PasswordGenerator.generate(**kwargs))
        return list(passwords)
