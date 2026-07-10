"""Directory and file bruteforce scanner."""

import asyncio

from core import load_wordlist
from core.http_client import HTTPClient
from core.models import ScanResult, Severity, Target
from modules.webscanner.base import WebScannerModule


class DirectoryBruteforcer(WebScannerModule):
    """Bruteforce directories and files."""

    name = "dirbrute"
    description = "Discover hidden directories and files"
    SECLISTS_RELATIVE_PATHS = (
        "Discovery/Web-Content/common.txt",
        "Discovery/Web-Content/common_directories.txt",
    )

    COMMON_PATHS = [
        # Directories
        "admin", "administrator", "login", "wp-admin", "wp-login.php",
        "phpmyadmin", "pma", "mysql", "database", "db",
        "backup", "backups", "bak", "old", "temp", "tmp",
        "test", "testing", "dev", "development", "staging",
        "api", "v1", "v2", "graphql", "rest",
        "config", "conf", "cfg", "settings",
        "uploads", "upload", "files", "media", "images", "img",
        "static", "assets", "js", "css", "fonts",
        "includes", "inc", "lib", "libs", "vendor", "node_modules",
        "cgi-bin", "scripts", "bin",
        ".git", ".svn", ".env", ".htaccess", ".htpasswd",
        "robots.txt", "sitemap.xml", "crossdomain.xml",
        "server-status", "server-info",
        "phpinfo.php", "info.php", "test.php",
        "console", "shell", "cmd",
        "logs", "log", "error_log", "access_log",
        "readme", "readme.txt", "readme.md", "changelog", "license",
        "install", "setup", "installer",
        "private", "secret", "internal", "confidential",
        # Common files
        "web.config", "config.php", "config.inc.php", "configuration.php",
        "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
        ".env", ".env.local", ".env.production", ".env.backup",
        "database.yml", "database.sql", "dump.sql", "backup.sql",
        "id_rsa", "id_rsa.pub", "authorized_keys",
        "composer.json", "package.json", "Gemfile",
    ]

    def __init__(
        self,
        wordlist: list[str] | None = None,
        extensions: list[str] | None = None,
        max_concurrent: int = 20,
        seclists_path: str | None = None,
    ):
        super().__init__()
        self.wordlist = wordlist or load_wordlist(
            self.SECLISTS_RELATIVE_PATHS,
            fallback=self.COMMON_PATHS,
            seclists_path=seclists_path,
        )
        self.extensions = extensions or ["", ".php", ".html", ".txt", ".bak", ".old"]
        self.max_concurrent = max_concurrent

    async def run(self, target: Target) -> ScanResult:
        """Bruteforce directories on target."""
        result = self.create_result(target)

        base_url = self._build_url(target).rstrip("/")
        self.logger.info(f"Starting directory bruteforce on {base_url}")

        found = []
        sensitive = []
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def check_path(path: str) -> dict | None:
            async with semaphore:
                url = f"{base_url}/{path}"
                try:
                    async with HTTPClient() as client:
                        response = await client.get(url)

                        # Consider 200, 301, 302, 403 as "found"
                        if response.status_code in (200, 301, 302, 403):
                            return {
                                "path": path,
                                "url": url,
                                "status": response.status_code,
                                "size": len(response.text),
                            }
                except Exception:
                    pass
                return None

        # Build path list with extensions
        paths_to_check = []
        for path in self.wordlist:
            if "." in path:
                paths_to_check.append(path)
            else:
                for ext in self.extensions:
                    paths_to_check.append(f"{path}{ext}")

        self.logger.info(f"Checking {len(paths_to_check)} paths...")

        # Run checks
        tasks = [check_path(p) for p in paths_to_check]
        results = await asyncio.gather(*tasks)

        found = [r for r in results if r is not None]

        # Categorize findings
        sensitive_patterns = [
            ".git", ".env", ".htpasswd", "config", "backup", "dump",
            "database", "private", "secret", "admin", "phpinfo",
            "id_rsa", "password", "credential",
        ]

        for item in found:
            if any(p in item["path"].lower() for p in sensitive_patterns):
                sensitive.append(item)

        result.raw_data["found"] = found
        result.raw_data["checked_count"] = len(paths_to_check)

        if found:
            result.add_finding(
                title="Directories/Files Discovered",
                description=f"Found {len(found)} accessible path(s)",
                severity=Severity.INFO,
                data={"paths": [f["path"] for f in found]},
            )

        if sensitive:
            result.add_finding(
                title="Sensitive Paths Exposed",
                description=f"Found {len(sensitive)} potentially sensitive path(s)",
                severity=Severity.HIGH,
                data={"paths": sensitive},
            )

        # Check for specific high-risk items
        git_exposed = any(f["path"] == ".git" and f["status"] == 200 for f in found)
        env_exposed = any(".env" in f["path"] and f["status"] == 200 for f in found)

        if git_exposed:
            result.add_finding(
                title="Git Repository Exposed",
                description=".git directory is publicly accessible - source code leak",
                severity=Severity.CRITICAL,
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"],
            )

        if env_exposed:
            result.add_finding(
                title="Environment File Exposed",
                description=".env file is publicly accessible - credentials may be leaked",
                severity=Severity.CRITICAL,
            )

        result.complete()
        return result

    def _build_url(self, target: Target) -> str:
        if target.target_type == "url":
            return target.value
        return f"https://{target.value}"
