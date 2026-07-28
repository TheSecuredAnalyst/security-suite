"""Tests for scheduler persistence (schedules, job history, reports)."""

import json
from datetime import datetime, timedelta

import pytest

from modules.scheduler.scheduler import (
    ScanJob,
    ScanScheduler,
    ScheduledScan,
    ScheduleFrequency,
)
from modules.scheduler.storage import ScheduleStorage


@pytest.fixture
def storage(tmp_path):
    return ScheduleStorage(storage_dir=tmp_path / "sched")


def _schedule(sid="s1", **overrides):
    data = {
        "id": sid,
        "name": "Weekly perimeter",
        "target": "example.com",
        "modules": ["dns", "ssl"],
        "frequency": ScheduleFrequency.WEEKLY,
    }
    data.update(overrides)
    return ScheduledScan(**data)


def _job(jid="j1", **overrides):
    data = {
        "id": jid,
        "schedule_id": "s1",
        "target": "example.com",
        "started_at": datetime(2026, 7, 1, 10, 0, 0),
        "status": "completed",
        "findings_count": 3,
    }
    data.update(overrides)
    return ScanJob(**data)


class TestInit:
    def test_creates_the_storage_directory(self, tmp_path):
        target = tmp_path / "nested" / "sched"
        ScheduleStorage(storage_dir=target)
        assert target.is_dir()

    def test_sets_expected_file_paths(self, storage):
        assert storage.schedules_file.name == "schedules.json"
        assert storage.jobs_file.name == "jobs.json"

    def test_defaults_to_settings_data_dir(self, tmp_path, monkeypatch):
        import modules.scheduler.storage as storage_module

        class FakeSettings:
            data_dir = tmp_path / "from-settings"

        monkeypatch.setattr(storage_module, "get_settings", lambda: FakeSettings())
        assert ScheduleStorage().storage_dir == tmp_path / "from-settings" / "scheduler"


class TestSchedules:
    def test_save_returns_true(self, storage):
        assert storage.save_schedules({"s1": _schedule()}) is True

    def test_save_then_load_round_trips(self, storage):
        storage.save_schedules({"s1": _schedule()})
        loaded = storage.load_schedules()
        assert set(loaded) == {"s1"}
        assert loaded["s1"].name == "Weekly perimeter"
        assert loaded["s1"].frequency == ScheduleFrequency.WEEKLY

    def test_round_trip_preserves_optional_fields(self, storage):
        sched = _schedule(
            cron_expression="0 3 * * *",
            frequency=ScheduleFrequency.CUSTOM,
            notify_webhook="https://hooks.example/x",
            siem_export=True,
            tags=["prod", "external"],
            run_count=7,
        )
        storage.save_schedules({"s1": sched})
        loaded = storage.load_schedules()["s1"]
        assert loaded.cron_expression == "0 3 * * *"
        assert loaded.notify_webhook == "https://hooks.example/x"
        assert loaded.siem_export is True
        assert loaded.tags == ["prod", "external"]
        assert loaded.run_count == 7

    def test_round_trip_preserves_datetimes(self, storage):
        last = datetime(2026, 6, 1, 12, 30)
        nxt = datetime(2026, 6, 8, 12, 30)
        storage.save_schedules({"s1": _schedule(last_run=last, next_run=nxt)})
        loaded = storage.load_schedules()["s1"]
        assert loaded.last_run == last
        assert loaded.next_run == nxt

    def test_load_missing_file_returns_empty(self, storage):
        assert storage.load_schedules() == {}

    def test_load_corrupt_json_returns_empty(self, storage):
        storage.schedules_file.write_text("{not json")
        assert storage.load_schedules() == {}

    def test_one_bad_entry_does_not_discard_the_rest(self, storage):
        storage.save_schedules({"good": _schedule("good")})
        data = json.loads(storage.schedules_file.read_text())
        data["bad"] = {"id": "bad"}  # missing required keys
        storage.schedules_file.write_text(json.dumps(data))
        loaded = storage.load_schedules()
        assert set(loaded) == {"good"}

    def test_save_empty_dict(self, storage):
        assert storage.save_schedules({}) is True
        assert storage.load_schedules() == {}

    def test_save_failure_returns_false(self, storage, monkeypatch):
        monkeypatch.setattr(
            type(storage.schedules_file), "write_text",
            lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")),
        )
        assert storage.save_schedules({"s1": _schedule()}) is False


class TestJobs:
    def test_save_then_load_round_trips(self, storage):
        storage.save_jobs({"j1": _job()})
        loaded = storage.load_jobs()
        assert set(loaded) == {"j1"}
        assert loaded["j1"].findings_count == 3
        assert loaded["j1"].status == "completed"

    def test_completed_at_round_trips(self, storage):
        done = datetime(2026, 7, 1, 10, 5, 0)
        storage.save_jobs({"j1": _job(completed_at=done)})
        assert storage.load_jobs()["j1"].completed_at == done

    def test_null_completed_at_round_trips(self, storage):
        storage.save_jobs({"j1": _job(completed_at=None)})
        assert storage.load_jobs()["j1"].completed_at is None

    def test_error_field_round_trips(self, storage):
        storage.save_jobs({"j1": _job(status="failed", error="connection refused")})
        loaded = storage.load_jobs()["j1"]
        assert loaded.status == "failed"
        assert loaded.error == "connection refused"

    def test_retention_keeps_the_most_recent_jobs(self, storage):
        base = datetime(2026, 7, 1)
        jobs = {
            f"j{i}": _job(f"j{i}", started_at=base + timedelta(hours=i))
            for i in range(10)
        }
        storage.save_jobs(jobs, max_jobs=3)
        loaded = storage.load_jobs()
        assert set(loaded) == {"j9", "j8", "j7"}

    def test_retention_default_keeps_everything_small(self, storage):
        jobs = {f"j{i}": _job(f"j{i}") for i in range(5)}
        storage.save_jobs(jobs)
        assert len(storage.load_jobs()) == 5

    def test_load_missing_file_returns_empty(self, storage):
        assert storage.load_jobs() == {}

    def test_load_corrupt_json_returns_empty(self, storage):
        storage.jobs_file.write_text("[[[")
        assert storage.load_jobs() == {}

    def test_one_bad_record_does_not_discard_the_rest(self, storage):
        storage.save_jobs({"j1": _job()})
        data = json.loads(storage.jobs_file.read_text())
        data.append({"id": "broken"})  # missing required keys
        storage.jobs_file.write_text(json.dumps(data))
        assert set(storage.load_jobs()) == {"j1"}

    def test_results_are_not_persisted(self, storage):
        """ScanJob.results is in-memory only — it must not break serialisation."""
        storage.save_jobs({"j1": _job(results=[object()])})
        assert storage.load_jobs()["j1"].results == []


class TestClearJobs:
    def test_removes_records_older_than_the_cutoff(self, storage):
        now = datetime.now()
        storage.save_jobs({
            "old": _job("old", started_at=now - timedelta(days=60)),
            "new": _job("new", started_at=now - timedelta(days=1)),
        })
        assert storage.clear_jobs(older_than_days=30) == 1
        assert set(storage.load_jobs()) == {"new"}

    def test_returns_zero_when_nothing_is_old(self, storage):
        storage.save_jobs({"new": _job("new", started_at=datetime.now())})
        assert storage.clear_jobs(older_than_days=30) == 0

    def test_returns_zero_when_file_is_missing(self, storage):
        assert storage.clear_jobs() == 0

    def test_returns_zero_on_corrupt_file(self, storage):
        storage.jobs_file.write_text("not json")
        assert storage.clear_jobs() == 0


class TestSchedulerIntegration:
    def test_attach_loads_state_into_the_scheduler(self, storage):
        storage.save_schedules({"s1": _schedule()})
        storage.save_jobs({"j1": _job()})

        scheduler = ScanScheduler()
        storage.attach_to_scheduler(scheduler)

        assert set(scheduler.schedules) == {"s1"}
        assert set(scheduler.jobs) == {"j1"}

    def test_attach_on_empty_storage_yields_empty_state(self, storage):
        scheduler = ScanScheduler()
        storage.attach_to_scheduler(scheduler)
        assert scheduler.schedules == {}
        assert scheduler.jobs == {}

    def test_sync_persists_scheduler_state(self, storage):
        scheduler = ScanScheduler()
        scheduler.schedules = {"s1": _schedule()}
        scheduler.jobs = {"j1": _job()}

        storage.sync_from_scheduler(scheduler)

        assert set(storage.load_schedules()) == {"s1"}
        assert set(storage.load_jobs()) == {"j1"}

    def test_sync_then_attach_is_a_full_round_trip(self, storage):
        original = ScanScheduler()
        original.schedules = {"s1": _schedule()}
        original.jobs = {"j1": _job()}
        storage.sync_from_scheduler(original)

        restored = ScanScheduler()
        storage.attach_to_scheduler(restored)

        assert restored.schedules["s1"].target == "example.com"
        assert restored.jobs["j1"].findings_count == 3


class TestExportReport:
    def test_writes_a_report_file(self, storage, tmp_path):
        storage.save_schedules({"s1": _schedule()})
        storage.save_jobs({"j1": _job()})
        out = tmp_path / "report.json"

        assert storage.export_report(out) is True
        assert out.exists()

    def test_summary_counts_are_correct(self, storage, tmp_path):
        storage.save_schedules({
            "on": _schedule("on", enabled=True),
            "off": _schedule("off", enabled=False),
        })
        storage.save_jobs({
            "ok": _job("ok", status="completed", findings_count=3),
            "bad": _job("bad", status="failed", findings_count=0),
        })
        out = tmp_path / "report.json"
        storage.export_report(out)

        summary = json.loads(out.read_text())["summary"]
        assert summary["total_schedules"] == 2
        assert summary["enabled_schedules"] == 1
        assert summary["total_jobs"] == 2
        assert summary["completed_jobs"] == 1
        assert summary["failed_jobs"] == 1
        assert summary["total_findings"] == 3

    def test_recent_jobs_are_newest_first(self, storage, tmp_path):
        base = datetime(2026, 7, 1)
        storage.save_jobs({
            "a": _job("a", started_at=base),
            "b": _job("b", started_at=base + timedelta(hours=1)),
        })
        out = tmp_path / "report.json"
        storage.export_report(out)

        ids = [j["id"] for j in json.loads(out.read_text())["recent_jobs"]]
        assert ids == ["b", "a"]

    def test_recent_jobs_are_capped_at_100(self, storage, tmp_path):
        base = datetime(2026, 7, 1)
        jobs = {
            f"j{i}": _job(f"j{i}", started_at=base + timedelta(minutes=i))
            for i in range(150)
        }
        storage.save_jobs(jobs)
        out = tmp_path / "report.json"
        storage.export_report(out)

        assert len(json.loads(out.read_text())["recent_jobs"]) == 100

    def test_empty_storage_produces_a_zeroed_report(self, storage, tmp_path):
        out = tmp_path / "report.json"
        assert storage.export_report(out) is True
        summary = json.loads(out.read_text())["summary"]
        assert summary["total_schedules"] == 0
        assert summary["total_jobs"] == 0

    def test_unwritable_path_returns_false(self, storage, tmp_path):
        assert storage.export_report(tmp_path / "no" / "such" / "dir" / "r.json") is False
