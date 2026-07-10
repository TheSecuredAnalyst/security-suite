"""Web crawler for discovering pages and endpoints."""

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.http_client import HTTPClient
from core.models import ScanResult, Severity, Target
from modules.webscanner.base import WebScannerModule


class WebCrawler(WebScannerModule):
    """Crawl website to discover pages, forms, and endpoints."""

    name = "crawler"
    description = "Crawl website to discover pages, forms, and API endpoints"

    def __init__(self, max_pages: int = 100, max_depth: int = 3):
        super().__init__()
        self.max_pages = max_pages
        self.max_depth = max_depth

    async def run(self, target: Target) -> ScanResult:
        """Crawl target website."""
        result = self.create_result(target)

        base_url = self._build_url(target)
        base_domain = urlparse(base_url).netloc
        self.logger.info(f"Starting crawl of {base_url}")

        visited: set[str] = set()
        to_visit: list[tuple[str, int]] = [(base_url, 0)]  # (url, depth)
        pages: list[dict] = []
        forms: list[dict] = []
        endpoints: set[str] = set()
        external_links: set[str] = set()

        try:
            async with HTTPClient() as client:
                while to_visit and len(visited) < self.max_pages:
                    url, depth = to_visit.pop(0)

                    if url in visited or depth > self.max_depth:
                        continue

                    visited.add(url)

                    try:
                        response = await client.get(url)

                        if "text/html" not in response.headers.get("content-type", ""):
                            continue

                        page_info = {
                            "url": str(response.url),
                            "status": response.status_code,
                            "title": None,
                            "depth": depth,
                        }

                        soup = BeautifulSoup(response.text, "lxml")

                        # Get title
                        title_tag = soup.find("title")
                        if title_tag:
                            page_info["title"] = title_tag.text.strip()

                        pages.append(page_info)

                        # Extract links
                        for link in soup.find_all("a", href=True):
                            href = link["href"]
                            full_url = urljoin(url, href)
                            parsed = urlparse(full_url)

                            # Skip non-http, anchors, etc
                            if parsed.scheme not in ("http", "https"):
                                continue

                            # Clean URL (remove fragment)
                            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                            if parsed.query:
                                clean_url += f"?{parsed.query}"

                            if parsed.netloc == base_domain:
                                if clean_url not in visited:
                                    to_visit.append((clean_url, depth + 1))
                            else:
                                external_links.add(parsed.netloc)

                        # Extract forms
                        for form in soup.find_all("form"):
                            form_info = {
                                "action": urljoin(url, form.get("action", "")),
                                "method": form.get("method", "get").upper(),
                                "inputs": [],
                                "page": url,
                            }

                            for inp in form.find_all(["input", "textarea", "select"]):
                                input_info = {
                                    "name": inp.get("name"),
                                    "type": inp.get("type", "text"),
                                    "id": inp.get("id"),
                                }
                                if input_info["name"]:
                                    form_info["inputs"].append(input_info)

                            if form_info["inputs"]:
                                forms.append(form_info)

                        # Extract API-like endpoints
                        for script in soup.find_all("script"):
                            script_text = script.string or ""
                            # Find URL patterns
                            api_patterns = re.findall(r'["\']/(api|v\d+)/[^"\']+["\']', script_text)
                            for pattern in api_patterns:
                                endpoints.add(pattern)

                    except Exception as e:
                        self.logger.debug(f"Error crawling {url}: {e}")

            result.raw_data["pages"] = pages
            result.raw_data["forms"] = forms
            result.raw_data["endpoints"] = list(endpoints)
            result.raw_data["external_links"] = list(external_links)

            result.add_finding(
                title="Crawl Complete",
                description=f"Discovered {len(pages)} page(s), {len(forms)} form(s)",
                severity=Severity.INFO,
                data={
                    "pages_count": len(pages),
                    "forms_count": len(forms),
                    "endpoints_count": len(endpoints),
                },
            )

            # Flag interesting forms
            sensitive_forms = [
                f for f in forms
                if any(
                    inp["type"] in ("password", "hidden") or
                    inp["name"] and any(kw in inp["name"].lower() for kw in ["pass", "token", "key", "secret"])
                    for inp in f["inputs"]
                )
            ]

            if sensitive_forms:
                result.add_finding(
                    title="Sensitive Forms Detected",
                    description=f"Found {len(sensitive_forms)} form(s) handling sensitive data",
                    severity=Severity.INFO,
                    data={"forms": sensitive_forms},
                )

        except Exception as e:
            result.errors.append(f"Crawl failed: {str(e)}")
            result.success = False

        result.complete()
        return result

    def _build_url(self, target: Target) -> str:
        if target.target_type == "url":
            return target.value
        return f"https://{target.value}"
