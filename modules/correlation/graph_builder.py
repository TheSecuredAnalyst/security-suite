"""Build an entity graph from a run's scan results.

The orchestrator populates the :class:`~core.entities.EntityGraph` as it goes,
but the ad-hoc ``secsuite correlate`` path just has a list of
:class:`~core.models.ScanResult`. This turns that flat output into a provenance
graph so host-scoped correlation rules can fire.

For a single-target correlate run everything hangs under one host root
(``host → service/url/vulnerability``); per-IP hosts across a netblock are the
orchestrator's job, not this one. Each finding's ``entity_id`` is set to the
node it produced, so a correlation can name the chain that led to it.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from core.entities import Entity, EntityGraph, EntityType
from core.models import Finding, ScanResult, Target

_PRODUCER = "correlation.graph_builder"


def _host_anchor(target: str) -> tuple[EntityType, str]:
    """The host entity type and value to anchor a single target under."""
    parsed = Target.from_string(target)
    if parsed.target_type == "ip":
        return EntityType.IP_ADDRESS, target
    if parsed.target_type == "url":
        return EntityType.HOSTNAME, (urlparse(target).hostname or target)
    return EntityType.DOMAIN, target


def _service_label(data: dict[str, Any]) -> str | None:
    """A stable "port/proto product" label from a service-shaped dict."""
    port = data.get("port")
    if not port:
        return None
    proto = data.get("protocol", "tcp")
    name = data.get("product") or data.get("name") or data.get("service") or ""
    return f"{port}/{proto} {name}".strip()


def _service_for_port(port: Any, host: Entity, graph: EntityGraph) -> Entity | None:
    """An existing SERVICE child of the host whose data port matches, if any."""
    if port is None:
        return None
    for child in graph.children(host):
        if child.entity_type == EntityType.SERVICE and child.data.get("port") == port:
            return child
    return None


def _classify(finding: Finding, host: Entity, graph: EntityGraph) -> Entity:
    """Create (or reuse) the entity a finding is about and return it.

    Identity-collapsing in EntityGraph.add means repeated services/urls merge
    into one node rather than piling up.
    """
    source = finding.source or ""
    data = finding.data or {}

    # Port/service discovery -> SERVICE node(s) under the host.
    if "port_scan" in source or source.endswith(".ports") or source == "ports":
        services = data.get("services")
        if isinstance(services, list) and services:
            first: Entity | None = None
            for svc in services:
                svc_data = svc if isinstance(svc, dict) else {}
                label = _service_label(svc_data) or str(svc)
                node = graph.add(host.child(EntityType.SERVICE, label, source, data=svc_data))
                first = first or node
            if first is not None:
                return first
        return graph.add(
            host.child(EntityType.SERVICE, _service_label(data) or finding.title, source, data=data)
        )

    # CVE / vulnerability findings -> VULNERABILITY node, nested under the
    # matching service when the finding names a port, else under the host.
    if "cve" in source or "vuln" in source:
        label = data.get("cve_id") or data.get("id") or finding.title
        parent = _service_for_port(data.get("port"), host, graph) or host
        return graph.add(parent.child(EntityType.VULNERABILITY, label, source, data=data))

    # Web findings -> a URL node (all web findings on one target share it).
    if source.startswith("webscanner"):
        url = data.get("url") or data.get("target") or host.value
        return graph.add(host.child(EntityType.URL, url, source, data=data))

    # Everything else is simply attributed to the host.
    return host


def build_graph(target: str, results: list[ScanResult]) -> EntityGraph:
    """Build a provenance graph from scan results, setting each finding's entity_id.

    Mutates the findings in ``results`` (sets ``entity_id``) and returns the graph.
    """
    graph = EntityGraph()
    host_type, host_value = _host_anchor(target)
    # The host is the root: a single-target run has one host, and a separate
    # TARGET wrapper with the same value would just double up in every chain.
    host = graph.add(Entity.root(host_value, host_type, _PRODUCER))

    for result in results:
        for finding in result.findings:
            entity = _classify(finding, host, graph)
            finding.entity_id = entity.id

    return graph
