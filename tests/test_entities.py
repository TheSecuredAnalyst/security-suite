"""Tests for the entity provenance graph."""

import pytest

from core.entities import Entity, EntityGraph, EntityType


def _chain() -> tuple[EntityGraph, Entity, Entity, Entity, Entity]:
    """target → host → service → cve, the shape a scan produces."""
    graph = EntityGraph()
    target = graph.add(Entity.root("acme.test", EntityType.TARGET, "orchestrator"))
    host = graph.add(target.child(EntityType.IP_ADDRESS, "10.0.0.5", "scanner"))
    service = graph.add(host.child(EntityType.SERVICE, "445/tcp microsoft-ds", "scanner"))
    cve = graph.add(service.child(EntityType.VULNERABILITY, "CVE-2017-0144", "cve_lookup"))
    return graph, target, host, service, cve


class TestEntity:
    def test_root_has_no_parent(self):
        entity = Entity.root("acme.test", EntityType.TARGET, "orchestrator")
        assert entity.parent_id is None
        assert entity.id

    def test_child_points_at_its_parent(self):
        parent = Entity.root("acme.test", EntityType.DOMAIN, "osint")
        child = parent.child(EntityType.IP_ADDRESS, "10.0.0.5", "dns_enum")
        assert child.parent_id == parent.id
        assert child.module == "dns_enum"

    def test_ids_are_unique_per_entity(self):
        first = Entity.root("a", EntityType.DOMAIN, "m")
        second = Entity.root("a", EntityType.DOMAIN, "m")
        assert first.id != second.id

    def test_confidence_is_bounded(self):
        with pytest.raises(ValueError):
            Entity.root("a", EntityType.DOMAIN, "m", confidence=101)

    def test_label(self):
        entity = Entity.root("10.0.0.5", EntityType.IP_ADDRESS, "scanner")
        assert entity.label() == "ip_address:10.0.0.5"


class TestGraphBuilding:
    def test_add_returns_the_entity(self):
        graph = EntityGraph()
        entity = graph.add(Entity.root("acme.test", EntityType.TARGET, "orchestrator"))
        assert graph.get(entity.id) is entity
        assert len(graph) == 1

    def test_same_type_and_value_collapse_to_one_node(self):
        graph = EntityGraph()
        first = graph.add(Entity.root("10.0.0.5", EntityType.IP_ADDRESS, "scanner"))
        second = graph.add(Entity.root("10.0.0.5", EntityType.IP_ADDRESS, "shodan"))

        assert second is first
        assert len(graph) == 1

    def test_a_second_sighting_records_its_module(self):
        graph = EntityGraph()
        entity = graph.add(Entity.root("10.0.0.5", EntityType.IP_ADDRESS, "scanner"))
        graph.add(Entity.root("10.0.0.5", EntityType.IP_ADDRESS, "shodan"))

        assert graph.sources(entity) == ["scanner", "shodan"]

    def test_a_second_sighting_merges_data(self):
        graph = EntityGraph()
        entity = graph.add(
            Entity.root("10.0.0.5", EntityType.IP_ADDRESS, "scanner", data={"asn": "AS1"})
        )
        graph.add(
            Entity.root("10.0.0.5", EntityType.IP_ADDRESS, "shodan", data={"org": "Acme"})
        )

        assert entity.data == {"asn": "AS1", "org": "Acme"}

    def test_one_in_scope_sighting_brings_the_node_in_scope(self):
        graph = EntityGraph()
        entity = graph.add(
            Entity.root("10.0.0.5", EntityType.IP_ADDRESS, "osint", in_scope=False)
        )
        graph.add(Entity.root("10.0.0.5", EntityType.IP_ADDRESS, "scanner", in_scope=True))

        assert entity.in_scope

    def test_same_value_different_type_stays_separate(self):
        graph = EntityGraph()
        graph.add(Entity.root("acme.test", EntityType.DOMAIN, "osint"))
        graph.add(Entity.root("acme.test", EntityType.HOSTNAME, "osint"))
        assert len(graph) == 2

    def test_children_are_tracked(self):
        graph, _target, host, service, _cve = _chain()
        assert graph.children(host) == [service]

    def test_membership(self):
        graph, target, *_ = _chain()
        assert target in graph
        assert target.id in graph
        assert Entity.root("nope", EntityType.DOMAIN, "m") not in graph


class TestProvenance:
    def test_ancestry_runs_root_first(self):
        graph, target, host, service, cve = _chain()
        assert graph.ancestry(cve) == [target, host, service, cve]

    def test_ancestry_accepts_an_id(self):
        graph, target, *_rest, cve = _chain()
        assert graph.ancestry(cve.id)[0] is target

    def test_root_ancestry_is_itself(self):
        graph, target, *_ = _chain()
        assert graph.ancestry(target) == [target]

    def test_attack_path_reads_as_a_chain(self):
        graph, *_rest, cve = _chain()
        assert graph.attack_path(cve) == (
            "acme.test → 10.0.0.5 → 445/tcp microsoft-ds → CVE-2017-0144"
        )

    def test_a_parent_cycle_does_not_hang(self):
        """A module parenting a node to its own descendant must not spin."""
        graph, _target, host, service, _cve = _chain()
        host.parent_id = service.id  # corrupt the graph on purpose

        chain = graph.ancestry(service)

        assert len(chain) == len({e.id for e in chain})

    def test_roots_and_by_type(self):
        graph, target, host, *_ = _chain()
        assert graph.roots() == [target]
        assert graph.by_type(EntityType.IP_ADDRESS) == [host]

    def test_find_by_identity(self):
        graph, _target, host, *_ = _chain()
        assert graph.find(EntityType.IP_ADDRESS, "10.0.0.5") is host
        assert graph.find(EntityType.IP_ADDRESS, "10.0.0.9") is None

    def test_stats_count_per_type(self):
        graph, *_ = _chain()
        assert graph.stats() == {
            "target": 1, "ip_address": 1, "service": 1, "vulnerability": 1
        }


class TestSerialisation:
    def test_to_dict_carries_paths_and_sources(self):
        graph, *_rest, cve = _chain()
        payload = graph.to_dict()

        assert payload["stats"]["vulnerability"] == 1
        cve_row = next(e for e in payload["entities"] if e["value"] == cve.value)
        assert cve_row["attack_path"].endswith("CVE-2017-0144")
        assert cve_row["sources"] == ["cve_lookup"]

    def test_round_trip_preserves_the_chain(self):
        graph, _target, _host, _service, cve = _chain()
        rebuilt = EntityGraph.from_entities(graph.all())

        assert len(rebuilt) == len(graph)
        assert rebuilt.attack_path(cve.id) == graph.attack_path(cve.id)

    def test_round_trip_survives_children_arriving_before_parents(self):
        graph, *_rest, cve = _chain()
        rebuilt = EntityGraph.from_entities(list(reversed(graph.all())))

        assert rebuilt.attack_path(cve.id) == graph.attack_path(cve.id)
        assert len(rebuilt.roots()) == 1

    def test_round_trip_tolerates_a_missing_parent(self):
        """An orphaned row must not lose the rest of the graph."""
        graph, _target, host, service, cve = _chain()
        orphaned = [e for e in graph.all() if e.id != host.id]

        rebuilt = EntityGraph.from_entities(orphaned)

        assert len(rebuilt) == 3
        assert rebuilt.attack_path(cve.id).startswith(service.value)
