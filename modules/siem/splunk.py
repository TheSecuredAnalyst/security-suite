"""Splunk HEC (HTTP Event Collector) exporter."""

import json

import httpx

from modules.siem.base import SIEMEvent, SIEMExporter


class SplunkExporter(SIEMExporter):
    """Export events to Splunk via HEC."""

    def __init__(
        self,
        hec_url: str,
        hec_token: str,
        index: str = "main",
        source: str = "security-suite",
        sourcetype: str = "security:scan",
        verify_ssl: bool = True,
        timeout: float = 10.0,
    ):
        """Initialize Splunk exporter.

        Args:
            hec_url: Splunk HEC URL (e.g., https://splunk:8088)
            hec_token: HEC authentication token
            index: Splunk index to send events to
            source: Event source identifier
            sourcetype: Event sourcetype
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
        """
        super().__init__()
        self.hec_url = hec_url.rstrip("/")
        self.hec_token = hec_token
        self.index = index
        self.source = source
        self.sourcetype = sourcetype
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    async def export(self, event: SIEMEvent) -> bool:
        """Export event to Splunk HEC.

        Args:
            event: Event to export

        Returns:
            True if successful
        """
        url = f"{self.hec_url}/services/collector/event"

        # Build HEC event payload
        payload = {
            "time": event.timestamp.timestamp(),
            "host": event.target or "security-suite",
            "source": self.source,
            "sourcetype": self.sourcetype,
            "index": self.index,
            "event": event.to_dict(),
        }

        headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=self.verify_ssl
            ) as client:
                response = await client.post(
                    url,
                    json=payload,
                    headers=headers,
                )

                if response.status_code == 200:
                    self.logger.debug(f"Event exported to Splunk: {event.event_type}")
                    return True
                else:
                    self.logger.error(
                        f"Splunk HEC error: {response.status_code} - {response.text}"
                    )
                    return False

        except Exception as e:
            self.logger.error(f"Splunk export failed: {e}")
            return False

    async def export_batch(self, events: list[SIEMEvent]) -> tuple[int, int]:
        """Export multiple events in a single request.

        Args:
            events: Events to export

        Returns:
            Tuple of (successful, failed) counts
        """
        if not events:
            return 0, 0

        url = f"{self.hec_url}/services/collector/event"

        # Build batch payload (newline-delimited JSON)
        payload_lines = []
        for event in events:
            payload = {
                "time": event.timestamp.timestamp(),
                "host": event.target or "security-suite",
                "source": self.source,
                "sourcetype": self.sourcetype,
                "index": self.index,
                "event": event.to_dict(),
            }
            payload_lines.append(json.dumps(payload))

        batch_payload = "\n".join(payload_lines)

        headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=self.verify_ssl
            ) as client:
                response = await client.post(
                    url,
                    content=batch_payload,
                    headers=headers,
                )

                if response.status_code == 200:
                    self.logger.info(f"Batch exported {len(events)} events to Splunk")
                    return len(events), 0
                else:
                    self.logger.error(
                        f"Splunk batch error: {response.status_code} - {response.text}"
                    )
                    return 0, len(events)

        except Exception as e:
            self.logger.error(f"Splunk batch export failed: {e}")
            return 0, len(events)

    async def test_connection(self) -> bool:
        """Test connection to Splunk HEC.

        Returns:
            True if connection successful
        """
        url = f"{self.hec_url}/services/collector/health"

        headers = {
            "Authorization": f"Splunk {self.hec_token}",
        }

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=self.verify_ssl
            ) as client:
                response = await client.get(url, headers=headers)
                return response.status_code == 200

        except Exception as e:
            self.logger.error(f"Splunk connection test failed: {e}")
            return False

    def get_config_info(self) -> dict:
        """Get exporter configuration info."""
        return {
            "type": "splunk",
            "url": self.hec_url,
            "index": self.index,
            "source": self.source,
            "sourcetype": self.sourcetype,
        }
