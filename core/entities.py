"""Entity graph: what we found, and what led us to it.

A scan currently produces a flat list of findings, which cannot answer the
question a report needs to answer — *how did we get here*. This module models
each discovered thing as an `Entity` that points at the entity it came from, so
a run builds a provenance graph rather than a pile:

    example.com  →  93.184.216.34  →  443/tcp https  →  CVE-2024-1234

Producers create children off the entity they were working from::

    host = graph.add(Entity.root("10.0.0.5", EntityType.IP_ADDRESS, "scanner"))
    svc = graph.add(host.child(EntityType.SERVICE, "445/tcp smb", "scanner"))
    graph.add(svc.child(EntityType.VULNERABILITY, "CVE-2017-0144", "cve_lookup"))

and `graph.attack_path(entity)` reads the chain back out.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    """Kinds of thing a module can discover.

    Deliberately coarse: a type earns its place when something downstream
    branches on it, not because a taxonomy would be tidier.
    """

    TARGET = "target"                # the scope root the operator asked for
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    NETBLOCK = "netblock"
    ASN = "asn"
    SERVICE = "service"              # a port/protocol/product on a host
    URL = "url"
    ENDPOINT = "endpoint"            # an API operation
    EMAIL = "email"
    USERNAME = "username"
    CERTIFICATE = "certificate"
    TECHNOLOGY = "technology"
    VULNERABILITY = "vulnerability"  # CVE or scanner finding
    CREDENTIAL = "credential"
    CLOUD_RESOURCE = "cloud_resource"
    DNS_RECORD = "dns_record"


class Entity(BaseModel):
    """One discovered thing, linked to whatever led us to it."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    entity_type: EntityType
    value: str
    module: str = Field(..., description="Module that produced this entity")
    parent_id: str | None = None
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: int = Field(default=100, ge=0, le=100)
    in_scope: bool = Field(
        default=True,
        description="False for related-but-out-of-scope entities we record without touching",
    )
    data: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def root(
        cls,
        value: str,
        entity_type: EntityType,
        module: str,
        **kwargs: Any,
    ) -> Entity:
        """Create an entity with no parent — the start of a chain."""
        return cls(entity_type=entity_type, value=value, module=module, **kwargs)

    def child(
        self,
        entity_type: EntityType,
        value: str,
        module: str,
        **kwargs: Any,
    ) -> Entity:
        """Create an entity discovered *from* this one."""
        return Entity(
            entity_type=entity_type,
            value=value,
            module=module,
            parent_id=self.id,
            **kwargs,
        )

    def label(self) -> str:
        """Short human-readable form, e.g. "ip_address:10.0.0.5"."""
        return f"{self.entity_type.value}:{self.value}"


class EntityGraph:
    """The entities discovered during one run, keyed by identity.

    Two entities with the same type and value are the same thing, so `add()`
    collapses them: the first parent wins (it is the path we actually took),
    later data is merged in, and every module that saw it is recorded in
    `sources`. That keeps the graph a tree per root while still crediting the
    modules that corroborated a node.
    """

    def __init__(self) -> None:
        self._entities: dict[str, Entity] = {}
        self._by_identity: dict[tuple[EntityType, str], str] = {}
        self._children: dict[str, list[str]] = {}
        self._sources: dict[str, list[str]] = {}

    # ── Building ──────────────────────────────────────────────────────────────

    def add(self, entity: Entity) -> Entity:
        """Add an entity, or merge into the existing one with the same identity.

        Returns the canonical entity — always use the return value as the
        parent for anything discovered from it.
        """
        identity = (entity.entity_type, entity.value)
        existing_id = self._by_identity.get(identity)

        if existing_id is not None:
            existing = self._entities[existing_id]
            existing.data.update(entity.data)
            if entity.module not in self._sources[existing_id]:
                self._sources[existing_id].append(entity.module)
            # A node first seen out of scope stays out of scope only if every
            # sighting agrees; one in-scope sighting is enough to include it.
            existing.in_scope = existing.in_scope or entity.in_scope
            return existing

        self._entities[entity.id] = entity
        self._by_identity[identity] = entity.id
        self._children.setdefault(entity.id, [])
        self._sources[entity.id] = [entity.module]

        if entity.parent_id is not None:
            self._children.setdefault(entity.parent_id, []).append(entity.id)

        return entity

    # ── Reading ───────────────────────────────────────────────────────────────

    def get(self, entity_id: str) -> Entity | None:
        return self._entities.get(entity_id)

    def find(self, entity_type: EntityType, value: str) -> Entity | None:
        """Look an entity up by identity."""
        entity_id = self._by_identity.get((entity_type, value))
        return self._entities.get(entity_id) if entity_id else None

    def all(self) -> list[Entity]:
        return list(self._entities.values())

    def by_type(self, entity_type: EntityType) -> list[Entity]:
        return [e for e in self._entities.values() if e.entity_type == entity_type]

    def roots(self) -> list[Entity]:
        return [e for e in self._entities.values() if e.parent_id is None]

    def children(self, entity: Entity | str) -> list[Entity]:
        entity_id = entity if isinstance(entity, str) else entity.id
        return [self._entities[c] for c in self._children.get(entity_id, [])]

    def sources(self, entity: Entity | str) -> list[str]:
        """Every module that reported this entity, in order of first sighting."""
        entity_id = entity if isinstance(entity, str) else entity.id
        return list(self._sources.get(entity_id, []))

    def ancestry(self, entity: Entity | str) -> list[Entity]:
        """The chain from the root down to `entity`, inclusive.

        A cycle would mean a module parented an entity to its own descendant;
        the walk is bounded by the visited set rather than trusting that.
        """
        current = self._entities.get(entity) if isinstance(entity, str) else entity
        chain: list[Entity] = []
        seen: set[str] = set()

        while current is not None and current.id not in seen:
            seen.add(current.id)
            chain.append(current)
            current = self._entities.get(current.parent_id) if current.parent_id else None

        return list(reversed(chain))

    def attack_path(self, entity: Entity | str, separator: str = " → ") -> str:
        """The ancestry rendered for a report, e.g. "10.0.0.5 → 445/tcp → CVE-…"."""
        return separator.join(e.value for e in self.ancestry(entity))

    def stats(self) -> dict[str, int]:
        """Count of entities per type, for run summaries."""
        counts: dict[str, int] = {}
        for entity in self._entities.values():
            counts[entity.entity_type.value] = counts.get(entity.entity_type.value, 0) + 1
        return counts

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "entities": [
                {
                    **entity.model_dump(mode="json"),
                    "sources": self.sources(entity),
                    "attack_path": self.attack_path(entity),
                }
                for entity in self._entities.values()
            ],
            "stats": self.stats(),
        }

    @classmethod
    def from_entities(cls, entities: list[Entity]) -> EntityGraph:
        """Rebuild a graph from stored entities.

        Parents are added before children so that no edge is dropped when the
        rows come back in arbitrary order.
        """
        graph = cls()
        by_id = {e.id: e for e in entities}
        added: set[str] = set()

        def _add(entity: Entity, seen: set[str]) -> None:
            if entity.id in added or entity.id in seen:
                return
            seen.add(entity.id)
            parent = by_id.get(entity.parent_id) if entity.parent_id else None
            if parent is not None:
                _add(parent, seen)
            graph._entities[entity.id] = entity
            graph._by_identity[(entity.entity_type, entity.value)] = entity.id
            graph._children.setdefault(entity.id, [])
            graph._sources.setdefault(entity.id, [entity.module])
            if entity.parent_id is not None:
                graph._children.setdefault(entity.parent_id, []).append(entity.id)
            added.add(entity.id)

        for entity in entities:
            _add(entity, set())

        return graph

    def __len__(self) -> int:
        return len(self._entities)

    def __contains__(self, entity: Entity | str) -> bool:
        entity_id = entity if isinstance(entity, str) else entity.id
        return entity_id in self._entities
