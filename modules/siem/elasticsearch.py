"""Elasticsearch exporter."""

import json
from datetime import datetime

import httpx

from modules.siem.base import SIEMEvent, SIEMExporter


class ElasticsearchExporter(SIEMExporter):
    """Export events to Elasticsearch."""

    def __init__(
        self,
        hosts: list[str],
        index_pattern: str = "security-suite-{date}",
        username: str | None = None,
        password: str | None = None,
        api_key: str | None = None,
        verify_ssl: bool = True,
        timeout: float = 10.0,
    ):
        """Initialize Elasticsearch exporter.

        Args:
            hosts: List of Elasticsearch hosts (e.g., ["https://es:9200"])
            index_pattern: Index pattern ({date} will be replaced with YYYY.MM.DD)
            username: Basic auth username
            password: Basic auth password
            api_key: API key for authentication (alternative to basic auth)
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
        """
        super().__init__()
        self.hosts = [h.rstrip("/") for h in hosts]
        self.index_pattern = index_pattern
        self.username = username
        self.password = password
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._current_host = 0

    def _get_index_name(self) -> str:
        """Get index name with date substitution."""
        date_str = datetime.now().strftime("%Y.%m.%d")
        return self.index_pattern.replace("{date}", date_str)

    def _get_host(self) -> str:
        """Get current host (simple round-robin)."""
        host = self.hosts[self._current_host]
        self._current_host = (self._current_host + 1) % len(self.hosts)
        return host

    def _get_headers(self) -> dict:
        """Get request headers with authentication."""
        headers = {"Content-Type": "application/json"}

        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"

        return headers

    def _get_auth(self) -> tuple | None:
        """Get basic auth tuple if configured."""
        if self.username and self.password:
            return (self.username, self.password)
        return None

    async def export(self, event: SIEMEvent) -> bool:
        """Export event to Elasticsearch.

        Args:
            event: Event to export

        Returns:
            True if successful
        """
        host = self._get_host()
        index = self._get_index_name()
        url = f"{host}/{index}/_doc"

        # Convert event to ES document
        doc = event.to_dict()
        doc["@timestamp"] = event.timestamp.isoformat()

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=self.verify_ssl
            ) as client:
                response = await client.post(
                    url,
                    json=doc,
                    headers=self._get_headers(),
                    auth=self._get_auth(),
                )

                if response.status_code in [200, 201]:
                    self.logger.debug(f"Event indexed to {index}")
                    return True
                else:
                    self.logger.error(
                        f"ES indexing error: {response.status_code} - {response.text}"
                    )
                    return False

        except Exception as e:
            self.logger.error(f"Elasticsearch export failed: {e}")
            return False

    async def export_batch(self, events: list[SIEMEvent]) -> tuple[int, int]:
        """Export multiple events using bulk API.

        Args:
            events: Events to export

        Returns:
            Tuple of (successful, failed) counts
        """
        if not events:
            return 0, 0

        host = self._get_host()
        index = self._get_index_name()
        url = f"{host}/_bulk"

        # Build bulk request body
        bulk_lines = []
        for event in events:
            # Action line
            bulk_lines.append(json.dumps({"index": {"_index": index}}))
            # Document line
            doc = event.to_dict()
            doc["@timestamp"] = event.timestamp.isoformat()
            bulk_lines.append(json.dumps(doc))

        bulk_body = "\n".join(bulk_lines) + "\n"

        headers = self._get_headers()
        headers["Content-Type"] = "application/x-ndjson"

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=self.verify_ssl
            ) as client:
                response = await client.post(
                    url,
                    content=bulk_body,
                    headers=headers,
                    auth=self._get_auth(),
                )

                if response.status_code == 200:
                    result = response.json()
                    if result.get("errors"):
                        # Count individual successes/failures
                        success = sum(
                            1 for item in result["items"]
                            if item.get("index", {}).get("status") in [200, 201]
                        )
                        failed = len(events) - success
                        self.logger.warning(f"Bulk indexing had {failed} failures")
                        return success, failed
                    else:
                        self.logger.info(f"Bulk indexed {len(events)} events")
                        return len(events), 0
                else:
                    self.logger.error(
                        f"ES bulk error: {response.status_code} - {response.text}"
                    )
                    return 0, len(events)

        except Exception as e:
            self.logger.error(f"Elasticsearch bulk export failed: {e}")
            return 0, len(events)

    async def test_connection(self) -> bool:
        """Test connection to Elasticsearch.

        Returns:
            True if connection successful
        """
        host = self._get_host()

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=self.verify_ssl
            ) as client:
                response = await client.get(
                    host,
                    headers=self._get_headers(),
                    auth=self._get_auth(),
                )

                if response.status_code == 200:
                    info = response.json()
                    self.logger.info(
                        f"Connected to ES {info.get('version', {}).get('number', 'unknown')}"
                    )
                    return True
                return False

        except Exception as e:
            self.logger.error(f"Elasticsearch connection test failed: {e}")
            return False

    async def create_index_template(self) -> bool:
        """Create index template for security events.

        Returns:
            True if successful
        """
        host = self._get_host()
        template_name = "security-suite"
        url = f"{host}/_index_template/{template_name}"

        template = {
            "index_patterns": ["security-suite-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1,
                },
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "event_type": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "source": {"type": "keyword"},
                        "target": {"type": "keyword"},
                        "module": {"type": "keyword"},
                        "message": {"type": "text"},
                        "finding_title": {"type": "text"},
                        "finding_description": {"type": "text"},
                        "risk_score": {"type": "float"},
                        "tags": {"type": "keyword"},
                    }
                }
            }
        }

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=self.verify_ssl
            ) as client:
                response = await client.put(
                    url,
                    json=template,
                    headers=self._get_headers(),
                    auth=self._get_auth(),
                )

                if response.status_code in [200, 201]:
                    self.logger.info("Created ES index template")
                    return True
                else:
                    self.logger.error(f"Template creation failed: {response.text}")
                    return False

        except Exception as e:
            self.logger.error(f"Index template creation failed: {e}")
            return False

    def get_config_info(self) -> dict:
        """Get exporter configuration info."""
        return {
            "type": "elasticsearch",
            "hosts": self.hosts,
            "index_pattern": self.index_pattern,
            "auth": "api_key" if self.api_key else "basic" if self.username else "none",
        }
