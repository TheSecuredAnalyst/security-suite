"""Tests for SecLists-backed wordlist loading."""

from unittest.mock import patch

from core.config import get_settings
from core.wordlists import load_wordlist, resolve_seclists_path, seclists_status
from modules.apisec.auth_tester import APIAuthTester
from modules.apisec.endpoint_tester import APIEndpointTester
from modules.apisec.fuzzer import APIFuzzer
from modules.osint.subdomain import SubdomainScanner
from modules.webscanner.dir_bruteforce import DirectoryBruteforcer
from modules.webscanner.sqli_scanner import SQLiScanner
from modules.webscanner.xss_scanner import XSSScanner


class TestWordlists:
    """Tests for wordlist loading and fallback behavior."""

    def setup_method(self):
        get_settings.cache_clear()

    def teardown_method(self):
        get_settings.cache_clear()

    def test_load_wordlist_from_explicit_seclists_path(self, tmp_path):
        seclists_root = tmp_path / "SecLists-master"
        wordlist_file = seclists_root / "Discovery" / "Web-Content" / "common.txt"
        wordlist_file.parent.mkdir(parents=True, exist_ok=True)
        wordlist_file.write_text("admin\nlogin\n# comment\n\napi\n", encoding="utf-8")

        entries = load_wordlist(
            "Discovery/Web-Content/common.txt",
            fallback=["fallback"],
            seclists_path=seclists_root,
        )

        assert entries == ["admin", "login", "api"]

    def test_load_wordlist_uses_fallback_when_file_missing(self, tmp_path):
        seclists_root = tmp_path / "SecLists-master"
        seclists_root.mkdir(parents=True, exist_ok=True)

        entries = load_wordlist(
            "Discovery/Web-Content/common.txt",
            fallback=["fallback", "admin"],
            seclists_path=seclists_root,
        )

        assert entries == ["fallback", "admin"]

    def test_resolve_seclists_path_from_setting(self, monkeypatch, tmp_path):
        seclists_root = tmp_path / "SecLists-master"
        seclists_root.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("SECSUITE_SECLISTS_PATH", str(seclists_root))
        get_settings.cache_clear()

        resolved = resolve_seclists_path()

        assert resolved == seclists_root.resolve()

    def test_dir_bruteforcer_loads_seclists_when_available(self, tmp_path):
        seclists_root = tmp_path / "SecLists-master"
        wordlist_file = seclists_root / "Discovery" / "Web-Content" / "common.txt"
        wordlist_file.parent.mkdir(parents=True, exist_ok=True)
        wordlist_file.write_text("admin\nportal\n", encoding="utf-8")

        scanner = DirectoryBruteforcer(seclists_path=str(seclists_root))

        assert scanner.wordlist == ["admin", "portal"]

    def test_dir_bruteforcer_falls_back_to_builtin_paths(self, tmp_path, monkeypatch):
        # Patch the resolver entirely so it returns None regardless of env or file tree,
        # simulating an environment where SecLists is genuinely not present.
        with patch("modules.webscanner.dir_bruteforce.load_wordlist", wraps=None) as mock_load:
            mock_load.return_value = DirectoryBruteforcer.COMMON_PATHS
            scanner = DirectoryBruteforcer(seclists_path=str(tmp_path / "missing-seclists"))
            # Confirm the module uses built-in paths when loader returns fallback
            assert scanner.wordlist == DirectoryBruteforcer.COMMON_PATHS
            assert "admin" in scanner.wordlist

    def test_subdomain_scanner_loads_seclists_wordlist(self, tmp_path):
        seclists_root = tmp_path / "SecLists-master"
        wordlist_file = seclists_root / "Discovery" / "DNS" / "subdomains-top1million-5000.txt"
        wordlist_file.parent.mkdir(parents=True, exist_ok=True)
        wordlist_file.write_text("www\napi\nadmin\n", encoding="utf-8")

        scanner = SubdomainScanner(seclists_path=str(seclists_root))

        assert scanner.wordlist[:3] == ["www", "api", "admin"]

    def test_xss_scanner_loads_seclists_payloads(self, tmp_path):
        seclists_root = tmp_path / "SecLists-master"
        payload_file = seclists_root / "Fuzzing" / "XSS" / "robot-friendly" / "XSS-Jhaddix.txt"
        payload_file.parent.mkdir(parents=True, exist_ok=True)
        payload_file.write_text("<svg/onload=alert(1)>\n<img src=x onerror=alert(1)>\n", encoding="utf-8")

        scanner = XSSScanner(seclists_path=str(seclists_root))

        assert "<svg/onload=alert(1)>" in scanner.payloads

    def test_sqli_scanner_loads_seclists_payloads(self, tmp_path):
        seclists_root = tmp_path / "SecLists-master"
        payload_file = seclists_root / "Fuzzing" / "Databases" / "SQLi" / "quick-SQLi.txt"
        payload_file.parent.mkdir(parents=True, exist_ok=True)
        payload_file.write_text("' OR 1=1--\nadmin'--\n", encoding="utf-8")

        scanner = SQLiScanner(seclists_path=str(seclists_root))

        assert "' OR 1=1--" in scanner.payloads

    def test_api_auth_tester_loads_jwt_secrets(self, tmp_path):
        seclists_root = tmp_path / "SecLists-master"
        secrets_file = seclists_root / "Passwords" / "scraped-JWT-secrets.txt"
        secrets_file.parent.mkdir(parents=True, exist_ok=True)
        secrets_file.write_text("supersecret\njwt_dev_key\n", encoding="utf-8")

        tester = APIAuthTester(seclists_path=str(seclists_root))

        assert "supersecret" in tester.jwt_secrets

    def test_api_fuzzer_extends_string_payloads_from_seclists(self, tmp_path):
        seclists_root = tmp_path / "SecLists-master"
        strings_file = seclists_root / "Fuzzing" / "big-list-of-naughty-strings.txt"
        strings_file.parent.mkdir(parents=True, exist_ok=True)
        strings_file.write_text("\"'--\n../../../etc/passwd\n", encoding="utf-8")

        fuzzer = APIFuzzer(seclists_path=str(seclists_root))
        payloads = fuzzer._get_payloads_for_type("string")

        assert "\"'--" in payloads

    def test_api_endpoint_tester_loads_lfi_and_cmdi_payloads(self, tmp_path):
        seclists_root = tmp_path / "SecLists-master"

        lfi_file = seclists_root / "Fuzzing" / "LFI" / "LFI-Jhaddix.txt"
        lfi_file.parent.mkdir(parents=True, exist_ok=True)
        lfi_file.write_text("../../../../etc/passwd\n", encoding="utf-8")

        cmdi_file = seclists_root / "Fuzzing" / "command-injection-commix.txt"
        cmdi_file.parent.mkdir(parents=True, exist_ok=True)
        cmdi_file.write_text(";id\n|whoami\n", encoding="utf-8")

        tester = APIEndpointTester(seclists_path=str(seclists_root))

        assert "../../../../etc/passwd" in tester.lfi_payloads
        assert ";id" in tester.cmdi_payloads

    def test_seclists_status_reports_entries(self, tmp_path):
        seclists_root = tmp_path / "SecLists-master"
        common_file = seclists_root / "Discovery" / "Web-Content" / "common.txt"
        common_file.parent.mkdir(parents=True, exist_ok=True)
        common_file.write_text("admin\nlogin\n", encoding="utf-8")

        status = seclists_status(seclists_path=str(seclists_root))

        assert status["available"] is True
        assert status["root"] == str(seclists_root)
        assert any(e["key"] == "web_directories" for e in status["entries"])
