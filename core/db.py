"""
SQLite persistence layer for the security loop.

Tables:
  runs        — one row per RedBlueOrchestrator.run() call
  findings    — one row per confirmed LoopFinding (deduped by ip+port)
  entities    — the run's provenance graph (see core.entities)
  remediations — AI-generated scripts linked to findings

DB location: ~/.secsuite/secsuite.db  (overridable via SECSUITE_DB env var)
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from core.logger import get_logger

if TYPE_CHECKING:
    from core.entities import EntityGraph

logger = get_logger("core.db")

_DEFAULT_DB = Path.home() / ".secsuite" / "secsuite.db"
_DB_PATH = Path(os.environ.get("SECSUITE_DB", str(_DEFAULT_DB)))

# Thread-local storage for connections
_local = threading.local()


def _get_connection() -> sqlite3.Connection:
    if not hasattr(_local, "conn") or _local.conn is None:
        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return _local.conn


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = _get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db() -> None:
    """Create tables if they don't exist."""
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                id              TEXT PRIMARY KEY,
                engagement_id   TEXT NOT NULL,
                operator        TEXT NOT NULL,
                target          TEXT NOT NULL,
                mode            TEXT NOT NULL,
                started_at      TEXT NOT NULL,
                completed_at    TEXT,
                risk_score      INTEGER DEFAULT 0,
                risk_color      TEXT DEFAULT 'UNKNOWN',
                total_hosts     INTEGER DEFAULT 0,
                total_services  INTEGER DEFAULT 0,
                total_cves      INTEGER DEFAULT 0,
                confirmed_exploitable INTEGER DEFAULT 0,
                already_exploited     INTEGER DEFAULT 0,
                remediations_generated INTEGER DEFAULT 0,
                remediations_applied   INTEGER DEFAULT 0,
                verified_closed        INTEGER DEFAULT 0,
                errors          TEXT DEFAULT '[]',
                report_path     TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id          TEXT NOT NULL REFERENCES runs(id),
                ip              TEXT NOT NULL,
                port            INTEGER NOT NULL,
                service         TEXT NOT NULL,
                version         TEXT,
                cve_id          TEXT,
                cvss_score      REAL DEFAULT 0,
                exploit_status  TEXT DEFAULT 'NOT_CHECKED',
                attack_tags     TEXT DEFAULT '[]',
                already_exploited INTEGER DEFAULT 0,
                hunt_evidence   TEXT DEFAULT '[]',
                created_at      TEXT NOT NULL,
                UNIQUE(run_id, ip, port)
            );

            CREATE TABLE IF NOT EXISTS remediations (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id               TEXT NOT NULL REFERENCES runs(id),
                finding_id           INTEGER REFERENCES findings(id),
                ip                   TEXT NOT NULL,
                port                 INTEGER NOT NULL,
                service              TEXT NOT NULL,
                cve_id               TEXT,
                safe                 INTEGER DEFAULT 0,
                explanation          TEXT,
                immediate_mitigation TEXT,
                permanent_fix        TEXT,
                rollback_script      TEXT,
                verification_command TEXT,
                warnings             TEXT DEFAULT '[]',
                model_used           TEXT,
                created_at           TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entities (
                id              TEXT NOT NULL,
                run_id          TEXT NOT NULL REFERENCES runs(id),
                entity_type     TEXT NOT NULL,
                value           TEXT NOT NULL,
                module          TEXT NOT NULL,
                parent_id       TEXT,
                discovered_at   TEXT NOT NULL,
                confidence      INTEGER DEFAULT 100,
                in_scope        INTEGER DEFAULT 1,
                sources         TEXT DEFAULT '[]',
                data            TEXT DEFAULT '{}',
                PRIMARY KEY (run_id, id)
            );

            CREATE INDEX IF NOT EXISTS idx_entities_run    ON entities(run_id);
            CREATE INDEX IF NOT EXISTS idx_entities_parent ON entities(run_id, parent_id);
            CREATE INDEX IF NOT EXISTS idx_entities_type   ON entities(entity_type, value);
            CREATE INDEX IF NOT EXISTS idx_findings_run   ON findings(run_id);
            CREATE INDEX IF NOT EXISTS idx_findings_ip    ON findings(ip, port);
            CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(exploit_status);
            CREATE INDEX IF NOT EXISTS idx_rems_run       ON remediations(run_id);
            CREATE INDEX IF NOT EXISTS idx_runs_started   ON runs(started_at DESC);
        """)
    logger.info(f"DB initialised: {_DB_PATH}")


# ── Run CRUD ───────────────────────────────────────────────────────────────────

def upsert_run(run_id: str, data: dict) -> None:
    """Insert or update a run record."""
    cols = [
        "id", "engagement_id", "operator", "target", "mode",
        "started_at", "completed_at", "risk_score", "risk_color",
        "total_hosts", "total_services", "total_cves",
        "confirmed_exploitable", "already_exploited",
        "remediations_generated", "remediations_applied", "verified_closed",
        "errors", "report_path",
    ]
    vals = [
        run_id,
        data.get("engagement_id", ""),
        data.get("operator", ""),
        data.get("target", ""),
        data.get("mode", ""),
        data.get("started_at", ""),
        data.get("completed_at"),
        data.get("risk_score", 0),
        data.get("risk_color", "UNKNOWN"),
        data.get("total_hosts", 0),
        data.get("total_services", 0),
        data.get("total_cves", 0),
        data.get("confirmed_exploitable", 0),
        data.get("already_exploited", 0),
        data.get("remediations_generated", 0),
        data.get("remediations_applied", 0),
        data.get("verified_closed", 0),
        json.dumps(data.get("errors", [])),
        data.get("report_path"),
    ]
    placeholders = ", ".join(["?"] * len(cols))
    updates = ", ".join(f"{c}=excluded.{c}" for c in cols if c != "id")
    sql = (
        f"INSERT INTO runs ({', '.join(cols)}) VALUES ({placeholders}) "
        f"ON CONFLICT(id) DO UPDATE SET {updates}"
    )
    with get_db() as conn:
        conn.execute(sql, vals)


def get_run(run_id: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return dict(row) if row else None


def list_runs(limit: int = 50) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# ── Finding CRUD ──────────────────────────────────────────────────────────────

def upsert_finding(run_id: str, finding: dict) -> int:
    """Insert or update a finding. Returns the finding row id."""
    sql = """
        INSERT INTO findings
            (run_id, ip, port, service, version, cve_id, cvss_score,
             exploit_status, attack_tags, already_exploited, hunt_evidence, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_id, ip, port) DO UPDATE SET
            cve_id=excluded.cve_id,
            cvss_score=excluded.cvss_score,
            exploit_status=excluded.exploit_status,
            attack_tags=excluded.attack_tags,
            already_exploited=excluded.already_exploited,
            hunt_evidence=excluded.hunt_evidence
        RETURNING id
    """
    with get_db() as conn:
        row = conn.execute(sql, [
            run_id,
            finding.get("ip", ""),
            finding.get("port", 0),
            finding.get("service", ""),
            finding.get("version", ""),
            finding.get("cve_id", ""),
            finding.get("cvss_score", 0.0),
            finding.get("exploit_status", "NOT_CHECKED"),
            json.dumps(finding.get("attack_tags", [])),
            int(finding.get("already_exploited", False)),
            json.dumps(finding.get("hunt_evidence", [])),
            datetime.now(timezone.utc).isoformat(),
        ]).fetchone()
        return row[0] if row else -1


def list_findings(run_id: str) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE run_id=? ORDER BY cvss_score DESC", (run_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def list_confirmed_findings(limit: int = 200) -> list[dict]:
    """All confirmed findings across all runs, newest first."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT f.*, r.engagement_id, r.operator, r.started_at as run_started
            FROM findings f
            JOIN runs r ON f.run_id = r.id
            WHERE f.exploit_status = 'CONFIRMED'
            ORDER BY r.started_at DESC, f.cvss_score DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]


# ── Entity CRUD ───────────────────────────────────────────────────────────────

def save_entities(run_id: str, graph: EntityGraph) -> int:
    """Persist a run's entity graph. Returns the number of rows written.

    Re-running a scan replaces that run's graph rather than appending to it,
    so a retried run does not leave two generations of nodes behind.
    """
    entities = graph.all()
    if not entities:
        return 0

    sql = """
        INSERT INTO entities
            (id, run_id, entity_type, value, module, parent_id,
             discovered_at, confidence, in_scope, sources, data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_id, id) DO UPDATE SET
            sources=excluded.sources,
            data=excluded.data,
            in_scope=excluded.in_scope
    """
    with get_db() as conn:
        conn.executemany(sql, [
            (
                e.id,
                run_id,
                e.entity_type.value,
                e.value,
                e.module,
                e.parent_id,
                e.discovered_at.isoformat(),
                e.confidence,
                int(e.in_scope),
                json.dumps(graph.sources(e)),
                json.dumps(e.data),
            )
            for e in entities
        ])
    return len(entities)


def list_entities(run_id: str) -> list[dict]:
    """Raw entity rows for a run, parents before children where possible."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM entities WHERE run_id=? ORDER BY discovered_at", (run_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def load_entity_graph(run_id: str) -> EntityGraph:
    """Rebuild a run's entity graph from the database."""
    from core.entities import Entity, EntityGraph

    entities = [
        Entity(
            id=row["id"],
            entity_type=row["entity_type"],
            value=row["value"],
            module=row["module"],
            parent_id=row["parent_id"],
            discovered_at=row["discovered_at"],
            confidence=row["confidence"],
            in_scope=bool(row["in_scope"]),
            data=json.loads(row["data"] or "{}"),
        )
        for row in list_entities(run_id)
    ]
    return EntityGraph.from_entities(entities)


# ── Remediation CRUD ──────────────────────────────────────────────────────────

def insert_remediation(run_id: str, finding_id: int, rem: dict) -> None:
    sql = """
        INSERT INTO remediations
            (run_id, finding_id, ip, port, service, cve_id, safe,
             explanation, immediate_mitigation, permanent_fix,
             rollback_script, verification_command, warnings, model_used, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    with get_db() as conn:
        conn.execute(sql, [
            run_id,
            finding_id,
            rem.get("ip", ""),
            rem.get("port", 0),
            rem.get("service", ""),
            rem.get("cve_id", ""),
            int(rem.get("safe", False)),
            rem.get("explanation", ""),
            rem.get("immediate_mitigation", ""),
            rem.get("permanent_fix", ""),
            rem.get("rollback_script", ""),
            rem.get("verification_command", ""),
            json.dumps(rem.get("warnings", [])),
            rem.get("model_used", ""),
            datetime.now(timezone.utc).isoformat(),
        ])


def list_remediations(run_id: str) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM remediations WHERE run_id=? ORDER BY id", (run_id,)
        ).fetchall()
        return [dict(r) for r in rows]


# ── Stats / Trend queries ─────────────────────────────────────────────────────

def get_stats() -> dict:
    """Aggregate stats across all runs."""
    with get_db() as conn:
        totals = conn.execute("""
            SELECT
                COUNT(*)                             AS total_runs,
                COALESCE(SUM(total_hosts), 0)        AS total_hosts,
                COALESCE(SUM(confirmed_exploitable), 0) AS total_confirmed,
                COALESCE(SUM(remediations_generated), 0) AS total_remediations,
                COALESCE(MAX(risk_score), 0)         AS max_risk_score
            FROM runs
        """).fetchone()

        severity_counts = conn.execute("""
            SELECT
                SUM(CASE WHEN cvss_score >= 9.0 THEN 1 ELSE 0 END) AS critical,
                SUM(CASE WHEN cvss_score >= 7.0 AND cvss_score < 9.0 THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN cvss_score >= 4.0 AND cvss_score < 7.0 THEN 1 ELSE 0 END) AS medium,
                SUM(CASE WHEN cvss_score > 0   AND cvss_score < 4.0 THEN 1 ELSE 0 END) AS low
            FROM findings
            WHERE exploit_status = 'CONFIRMED'
        """).fetchone()

        return {
            "total_runs": totals["total_runs"] or 0,
            "total_hosts": totals["total_hosts"] or 0,
            "total_confirmed": totals["total_confirmed"] or 0,
            "total_remediations": totals["total_remediations"] or 0,
            "max_risk_score": totals["max_risk_score"] or 0,
            "critical": severity_counts["critical"] or 0,
            "high": severity_counts["high"] or 0,
            "medium": severity_counts["medium"] or 0,
            "low": severity_counts["low"] or 0,
        }


def get_risk_trend(days: int = 30) -> list[dict]:
    """Risk score per run for the last N days."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT
                DATE(started_at) AS day,
                MAX(risk_score)  AS peak_risk,
                COUNT(*)         AS run_count
            FROM runs
            WHERE started_at >= DATE('now', ? || ' days')
            GROUP BY day
            ORDER BY day ASC
        """, (f"-{days}",)).fetchall()
        return [dict(r) for r in rows]


def get_exposure_trend(days: int = 30) -> list[dict]:
    """Confirmed exposures per run for the last N days."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT
                DATE(r.started_at)     AS day,
                COUNT(DISTINCT f.ip || ':' || f.port) AS unique_exposures
            FROM runs r
            JOIN findings f ON f.run_id = r.id AND f.exploit_status = 'CONFIRMED'
            WHERE r.started_at >= DATE('now', ? || ' days')
            GROUP BY day
            ORDER BY day ASC
        """, (f"-{days}",)).fetchall()
        return [dict(r) for r in rows]


# Initialise on import
init_db()
