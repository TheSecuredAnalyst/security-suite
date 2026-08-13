"""Tests for the SQLite persistence layer.

core.db resolves its database path at import time and calls init_db() as an
import side effect, so each test reloads the module against a temp path.
"""

import importlib
import json
import sqlite3

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    """A freshly initialised core.db bound to a throwaway database file."""
    monkeypatch.setenv("SECSUITE_DB", str(tmp_path / "test.db"))
    import core.db as db_module

    db_module = importlib.reload(db_module)
    yield db_module

    conn = getattr(db_module._local, "conn", None)
    if conn is not None:
        conn.close()
        db_module._local.conn = None


def _run(**overrides):
    data = {
        "engagement_id": "ENG-1",
        "operator": "tester",
        "target": "10.0.0.0/24",
        "mode": "recon",
        "started_at": "2026-07-01T10:00:00+00:00",
        "risk_score": 70,
        "risk_color": "HIGH",
        "total_hosts": 3,
        "confirmed_exploitable": 1,
        "remediations_generated": 2,
    }
    data.update(overrides)
    return data


def _finding(**overrides):
    data = {
        "ip": "10.0.0.5",
        "port": 22,
        "service": "ssh",
        "version": "OpenSSH 8.2",
        "cve_id": "CVE-2024-6387",
        "cvss_score": 8.1,
        "exploit_status": "CONFIRMED",
        "attack_tags": ["T1210"],
        "already_exploited": False,
        "hunt_evidence": ["auth.log"],
    }
    data.update(overrides)
    return data


class TestInitDB:
    def test_creates_expected_tables(self, db):
        with db.get_db() as conn:
            names = {
                r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        assert {"runs", "findings", "remediations"} <= names

    def test_is_idempotent(self, db):
        db.init_db()
        db.init_db()
        assert db.list_runs() == []

    def test_creates_the_database_file(self, db):
        assert db._DB_PATH.exists()


class TestRunCRUD:
    def test_insert_and_fetch(self, db):
        db.upsert_run("run-1", _run())
        row = db.get_run("run-1")
        assert row["engagement_id"] == "ENG-1"
        assert row["risk_score"] == 70

    def test_get_missing_run_returns_none(self, db):
        assert db.get_run("nope") is None

    def test_upsert_updates_existing_row(self, db):
        db.upsert_run("run-1", _run(risk_score=10))
        db.upsert_run("run-1", _run(risk_score=95, risk_color="CRITICAL"))
        row = db.get_run("run-1")
        assert row["risk_score"] == 95
        assert row["risk_color"] == "CRITICAL"
        assert len(db.list_runs()) == 1

    def test_errors_are_stored_as_json(self, db):
        db.upsert_run("run-1", _run(errors=["timeout", "refused"]))
        assert json.loads(db.get_run("run-1")["errors"]) == ["timeout", "refused"]

    def test_missing_fields_fall_back_to_defaults(self, db):
        db.upsert_run("run-1", {})
        row = db.get_run("run-1")
        assert row["risk_score"] == 0
        assert row["risk_color"] == "UNKNOWN"
        assert json.loads(row["errors"]) == []

    def test_list_runs_is_newest_first(self, db):
        db.upsert_run("old", _run(started_at="2026-01-01T00:00:00+00:00"))
        db.upsert_run("new", _run(started_at="2026-07-01T00:00:00+00:00"))
        assert [r["id"] for r in db.list_runs()] == ["new", "old"]

    def test_list_runs_respects_limit(self, db):
        for i in range(5):
            db.upsert_run(f"run-{i}", _run(started_at=f"2026-07-0{i + 1}T00:00:00+00:00"))
        assert len(db.list_runs(limit=2)) == 2

    def test_list_runs_empty(self, db):
        assert db.list_runs() == []


class TestFindingCRUD:
    def test_insert_returns_row_id(self, db):
        db.upsert_run("run-1", _run())
        assert db.upsert_finding("run-1", _finding()) > 0

    def test_insert_and_list(self, db):
        db.upsert_run("run-1", _run())
        db.upsert_finding("run-1", _finding())
        rows = db.list_findings("run-1")
        assert len(rows) == 1
        assert rows[0]["service"] == "ssh"

    def test_same_ip_port_is_deduplicated_within_a_run(self, db):
        db.upsert_run("run-1", _run())
        db.upsert_finding("run-1", _finding(cvss_score=5.0))
        db.upsert_finding("run-1", _finding(cvss_score=9.8, exploit_status="EXPLOITED"))
        rows = db.list_findings("run-1")
        assert len(rows) == 1
        assert rows[0]["cvss_score"] == 9.8
        assert rows[0]["exploit_status"] == "EXPLOITED"

    def test_same_ip_port_in_different_runs_are_separate(self, db):
        db.upsert_run("run-1", _run())
        db.upsert_run("run-2", _run())
        db.upsert_finding("run-1", _finding())
        db.upsert_finding("run-2", _finding())
        assert len(db.list_findings("run-1")) == 1
        assert len(db.list_findings("run-2")) == 1

    def test_list_findings_sorted_by_cvss_descending(self, db):
        db.upsert_run("run-1", _run())
        db.upsert_finding("run-1", _finding(port=22, cvss_score=4.0))
        db.upsert_finding("run-1", _finding(port=443, cvss_score=9.8))
        db.upsert_finding("run-1", _finding(port=80, cvss_score=7.5))
        assert [r["cvss_score"] for r in db.list_findings("run-1")] == [9.8, 7.5, 4.0]

    def test_json_fields_round_trip(self, db):
        db.upsert_run("run-1", _run())
        db.upsert_finding("run-1", _finding(attack_tags=["T1210", "T1021.004"]))
        row = db.list_findings("run-1")[0]
        assert json.loads(row["attack_tags"]) == ["T1210", "T1021.004"]

    def test_already_exploited_bool_is_stored_as_int(self, db):
        db.upsert_run("run-1", _run())
        db.upsert_finding("run-1", _finding(already_exploited=True))
        assert db.list_findings("run-1")[0]["already_exploited"] == 1

    def test_created_at_is_populated(self, db):
        db.upsert_run("run-1", _run())
        db.upsert_finding("run-1", _finding())
        assert db.list_findings("run-1")[0]["created_at"]

    def test_list_findings_for_unknown_run_is_empty(self, db):
        assert db.list_findings("nope") == []

    def test_list_confirmed_findings_filters_by_status(self, db):
        db.upsert_run("run-1", _run())
        db.upsert_finding("run-1", _finding(port=22, exploit_status="CONFIRMED"))
        db.upsert_finding("run-1", _finding(port=80, exploit_status="NOT_CHECKED"))
        rows = db.list_confirmed_findings()
        assert len(rows) == 1
        assert rows[0]["port"] == 22

    def test_list_confirmed_findings_joins_run_metadata(self, db):
        db.upsert_run("run-1", _run())
        db.upsert_finding("run-1", _finding())
        row = db.list_confirmed_findings()[0]
        assert row["engagement_id"] == "ENG-1"
        assert row["operator"] == "tester"

    def test_list_confirmed_findings_respects_limit(self, db):
        db.upsert_run("run-1", _run())
        for port in range(20, 25):
            db.upsert_finding("run-1", _finding(port=port))
        assert len(db.list_confirmed_findings(limit=2)) == 2


class TestRemediationCRUD:
    def test_insert_and_list(self, db):
        db.upsert_run("run-1", _run())
        fid = db.upsert_finding("run-1", _finding())
        db.insert_remediation("run-1", fid, {
            "ip": "10.0.0.5", "port": 22, "service": "ssh",
            "safe": True, "explanation": "patch openssh",
            "warnings": ["requires restart"], "model_used": "qwen2.5",
        })
        rows = db.list_remediations("run-1")
        assert len(rows) == 1
        assert rows[0]["safe"] == 1
        assert json.loads(rows[0]["warnings"]) == ["requires restart"]

    def test_defaults_applied_for_missing_fields(self, db):
        db.upsert_run("run-1", _run())
        fid = db.upsert_finding("run-1", _finding())
        db.insert_remediation("run-1", fid, {})
        row = db.list_remediations("run-1")[0]
        assert row["safe"] == 0
        assert row["ip"] == ""

    def test_multiple_remediations_ordered_by_id(self, db):
        db.upsert_run("run-1", _run())
        fid = db.upsert_finding("run-1", _finding())
        db.insert_remediation("run-1", fid, {"explanation": "first"})
        db.insert_remediation("run-1", fid, {"explanation": "second"})
        assert [r["explanation"] for r in db.list_remediations("run-1")] == ["first", "second"]

    def test_list_for_unknown_run_is_empty(self, db):
        assert db.list_remediations("nope") == []


class TestStats:
    def test_empty_database(self, db):
        stats = db.get_stats()
        assert stats["total_runs"] == 0
        assert stats["critical"] == 0

    def test_aggregates_run_totals(self, db):
        db.upsert_run("run-1", _run(total_hosts=3, confirmed_exploitable=1, remediations_generated=2))
        db.upsert_run("run-2", _run(total_hosts=5, confirmed_exploitable=4, remediations_generated=1))
        stats = db.get_stats()
        assert stats["total_runs"] == 2
        assert stats["total_hosts"] == 8
        assert stats["total_confirmed"] == 5
        assert stats["total_remediations"] == 3

    def test_max_risk_score_is_the_peak_not_the_sum(self, db):
        db.upsert_run("run-1", _run(risk_score=40))
        db.upsert_run("run-2", _run(risk_score=90))
        assert db.get_stats()["max_risk_score"] == 90

    def test_severity_buckets_by_cvss(self, db):
        db.upsert_run("run-1", _run())
        db.upsert_finding("run-1", _finding(port=1, cvss_score=9.5))
        db.upsert_finding("run-1", _finding(port=2, cvss_score=7.5))
        db.upsert_finding("run-1", _finding(port=3, cvss_score=5.0))
        db.upsert_finding("run-1", _finding(port=4, cvss_score=2.0))
        stats = db.get_stats()
        assert (stats["critical"], stats["high"], stats["medium"], stats["low"]) == (1, 1, 1, 1)

    def test_severity_buckets_ignore_unconfirmed_findings(self, db):
        db.upsert_run("run-1", _run())
        db.upsert_finding("run-1", _finding(port=1, cvss_score=9.5, exploit_status="NOT_CHECKED"))
        assert db.get_stats()["critical"] == 0

    def test_zero_cvss_is_not_counted_as_low(self, db):
        db.upsert_run("run-1", _run())
        db.upsert_finding("run-1", _finding(port=1, cvss_score=0.0))
        assert db.get_stats()["low"] == 0


class TestTrends:
    def test_risk_trend_empty(self, db):
        assert db.get_risk_trend() == []

    def test_risk_trend_groups_by_day(self, db):
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        db.upsert_run("run-1", _run(started_at=f"{today}T08:00:00+00:00", risk_score=40))
        db.upsert_run("run-2", _run(started_at=f"{today}T20:00:00+00:00", risk_score=90))
        trend = db.get_risk_trend()
        assert len(trend) == 1
        assert trend[0]["peak_risk"] == 90
        assert trend[0]["run_count"] == 2

    def test_risk_trend_excludes_runs_outside_the_window(self, db):
        db.upsert_run("old", _run(started_at="2020-01-01T00:00:00+00:00"))
        assert db.get_risk_trend(days=30) == []

    def test_exposure_trend_empty(self, db):
        assert db.get_exposure_trend() == []

    def test_exposure_trend_counts_unique_ip_port_pairs(self, db):
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        db.upsert_run("run-1", _run(started_at=f"{today}T08:00:00+00:00"))
        db.upsert_finding("run-1", _finding(ip="10.0.0.5", port=22))
        db.upsert_finding("run-1", _finding(ip="10.0.0.5", port=443))
        db.upsert_finding("run-1", _finding(ip="10.0.0.6", port=22))
        trend = db.get_exposure_trend()
        assert trend[0]["unique_exposures"] == 3

    def test_exposure_trend_ignores_unconfirmed(self, db):
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        db.upsert_run("run-1", _run(started_at=f"{today}T08:00:00+00:00"))
        db.upsert_finding("run-1", _finding(exploit_status="NOT_CHECKED"))
        assert db.get_exposure_trend() == []


class TestTransactions:
    def test_failed_statement_rolls_back(self, db):
        db.upsert_run("run-1", _run())
        with pytest.raises(sqlite3.OperationalError):
            with db.get_db() as conn:
                conn.execute("UPDATE runs SET risk_score=1 WHERE id='run-1'")
                conn.execute("SELECT * FROM table_that_does_not_exist")
        assert db.get_run("run-1")["risk_score"] == 70

    def test_successful_block_commits(self, db):
        with db.get_db() as conn:
            conn.execute(
                "INSERT INTO runs (id, engagement_id, operator, target, mode, started_at) "
                "VALUES ('x', 'e', 'o', 't', 'm', '2026-07-01T00:00:00+00:00')"
            )
        assert db.get_run("x") is not None

    def test_connection_is_reused_within_a_thread(self, db):
        with db.get_db() as first:
            pass
        with db.get_db() as second:
            pass
        assert first is second


class TestEntities:
    """The provenance graph must survive a round trip through SQLite."""

    def _graph(self):
        from core.entities import Entity, EntityGraph, EntityType

        graph = EntityGraph()
        target = graph.add(Entity.root("10.0.0.0/24", EntityType.TARGET, "orchestrator"))
        host = graph.add(target.child(EntityType.IP_ADDRESS, "10.0.0.5", "scanner"))
        service = graph.add(host.child(EntityType.SERVICE, "22/tcp ssh", "scanner"))
        graph.add(service.child(EntityType.VULNERABILITY, "CVE-2024-6387", "cve_lookup"))
        graph.add(Entity.root("10.0.0.5", EntityType.IP_ADDRESS, "shodan"))  # second sighting
        return graph

    def test_save_and_reload_preserves_the_chain(self, db):
        from core.entities import EntityType

        db.upsert_run("run-1", _run())
        graph = self._graph()

        written = db.save_entities("run-1", graph)
        reloaded = db.load_entity_graph("run-1")

        assert written == len(graph)
        cve = reloaded.find(EntityType.VULNERABILITY, "CVE-2024-6387")
        assert reloaded.attack_path(cve) == (
            "10.0.0.0/24 → 10.0.0.5 → 22/tcp ssh → CVE-2024-6387"
        )

    def test_stores_one_row_per_deduped_entity(self, db):
        db.upsert_run("run-1", _run())
        db.save_entities("run-1", self._graph())

        rows = db.list_entities("run-1")
        values = [r["value"] for r in rows]

        assert len(rows) == 4
        assert values.count("10.0.0.5") == 1

    def test_records_every_module_that_saw_an_entity(self, db):
        db.upsert_run("run-1", _run())
        db.save_entities("run-1", self._graph())

        host_row = next(r for r in db.list_entities("run-1") if r["value"] == "10.0.0.5")
        assert json.loads(host_row["sources"]) == ["scanner", "shodan"]

    def test_saving_twice_does_not_duplicate_rows(self, db):
        db.upsert_run("run-1", _run())
        graph = self._graph()

        db.save_entities("run-1", graph)
        db.save_entities("run-1", graph)

        assert len(db.list_entities("run-1")) == len(graph)

    def test_runs_do_not_share_entities(self, db):
        db.upsert_run("run-1", _run())
        db.upsert_run("run-2", _run())
        db.save_entities("run-1", self._graph())

        assert db.list_entities("run-2") == []
        assert len(db.load_entity_graph("run-2")) == 0

    def test_empty_graph_writes_nothing(self, db):
        from core.entities import EntityGraph

        db.upsert_run("run-1", _run())
        assert db.save_entities("run-1", EntityGraph()) == 0
