"""Technology detection module."""

import re

from core.http_client import HTTPClient
from core.models import ScanResult, Severity, Target
from modules.osint.base import OSINTModule


class TechDetector(OSINTModule):
    """Detect web technologies, frameworks, and CMS."""

    name = "tech_detect"
    description = "Identify web technologies, frameworks, and CMS platforms"

    SIGNATURES = {
        "WordPress": {
            "headers": {"x-powered-by": r"WordPress"},
            "body": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
            "meta": [r'name="generator" content="WordPress'],
        },
        "Drupal": {
            "headers": {"x-generator": r"Drupal", "x-drupal-cache": r".*"},
            "body": [r"/sites/default/files/", r"Drupal.settings"],
        },
        "Joomla": {
            "body": [r"/media/jui/", r"/administrator/"],
            "meta": [r'name="generator" content="Joomla'],
        },
        "React": {"body": [r"react\.production\.min\.js", r"_reactRootContainer"]},
        "Vue.js": {"body": [r"vue\.min\.js", r"vue\.runtime", r"__VUE__"]},
        "Angular": {"body": [r"ng-version=", r"angular\.min\.js"]},
        "nginx": {"headers": {"server": r"nginx"}},
        "Apache": {"headers": {"server": r"Apache"}},
        "IIS": {"headers": {"server": r"Microsoft-IIS"}},
        "Cloudflare": {"headers": {"server": r"cloudflare", "cf-ray": r".*"}},
        "PHP": {"headers": {"x-powered-by": r"PHP"}},
        "ASP.NET": {"headers": {"x-powered-by": r"ASP\.NET"}},
        "Node.js": {"headers": {"x-powered-by": r"Express"}},
        "Laravel": {"body": [r"laravel"], "cookies": ["laravel_session"]},
        "Django": {"body": [r"csrfmiddlewaretoken"], "cookies": ["csrftoken"]},
    }

    async def run(self, target: Target) -> ScanResult:
        """Detect technologies used by target."""
        result = self.create_result(target)
        url = self._build_url(target)
        self.logger.info(f"Detecting technologies for {url}")

        try:
            async with HTTPClient() as client:
                response = await client.get(url)
                headers = {k.lower(): v for k, v in response.headers.items()}
                body = response.text
                cookies = [c.name for c in response.cookies.jar]

                result.raw_data["url"] = str(response.url)
                result.raw_data["status_code"] = response.status_code

                detected = []

                for tech, sigs in self.SIGNATURES.items():
                    if self._check_signatures(sigs, headers, body, cookies):
                        detected.append(tech)

                result.raw_data["technologies"] = detected

                if detected:
                    result.add_finding(
                        title="Technologies Detected",
                        description=f"Identified {len(detected)} technology/technologies",
                        severity=Severity.INFO,
                        data={"technologies": detected},
                    )

        except Exception as e:
            result.errors.append(f"Failed to detect technologies: {str(e)}")
            result.success = False

        result.complete()
        return result

    def _check_signatures(self, sigs: dict, headers: dict, body: str, cookies: list) -> bool:
        if "headers" in sigs:
            for header, pattern in sigs["headers"].items():
                if header in headers and re.search(pattern, headers[header], re.I):
                    return True
        if "body" in sigs:
            for pattern in sigs["body"]:
                if re.search(pattern, body, re.I):
                    return True
        if "meta" in sigs:
            for pattern in sigs["meta"]:
                if re.search(pattern, body, re.I):
                    return True
        if "cookies" in sigs:
            for cookie in sigs["cookies"]:
                if cookie in cookies:
                    return True
        return False

    def _build_url(self, target: Target) -> str:
        if target.target_type == "url":
            return target.value
        return f"https://{target.value}"
