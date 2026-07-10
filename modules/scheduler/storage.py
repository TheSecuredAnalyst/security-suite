"""Storage backend for scheduler data."""

import json
from datetime import datetime
from pathlib import Path

from core.config import get_settings
from core.logger import get_logger
from modules.scheduler.scheduler import ScanJob, ScanScheduler, ScheduledScan


class ScheduleStorage:
    """Persistent storage for schedules and job history."""

    def __init__(self, storage_dir: Path | None = None):
        """Initialize storage.

        Args:
            storage_dir: Directory for storage files
        """
        self.logger = get_logger("scheduler.storage")

        if storage_dir:
            self.storage_dir = Path(storage_dir)
        else:
            self.storage_dir = get_settings().data_dir / "scheduler"

        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.schedules_file = self.storage_dir / "schedules.json"
        self.jobs_file = self.storage_dir / "jobs.json"

    def save_schedules(self, schedules: dict[str, ScheduledScan]) -> bool:
        """Save schedules to disk.

        Args:
            schedules: Dictionary of schedules

        Returns:
            True if successful
        """
        try:
            data = {sid: s.to_dict() for sid, s in schedules.items()}
            self.schedules_file.write_text(json.dumps(data, indent=2))
            self.logger.debug(f"Saved {len(schedules)} schedules")
            return True

        except Exception as e:
            self.logger.error(f"Failed to save schedules: {e}")
            return False

    def load_schedules(self) -> dict[str, ScheduledScan]:
        """Load schedules from disk.

        Returns:
            Dictionary of schedules
        """
        if not self.schedules_file.exists():
            return {}

        try:
            data = json.loads(self.schedules_file.read_text())
            schedules = {}
            for sid, sdata in data.items():
                try:
                    schedules[sid] = ScheduledScan.from_dict(sdata)
                except Exception as e:
                    self.logger.warning(f"Failed to load schedule {sid}: {e}")

            self.logger.info(f"Loaded {len(schedules)} schedules")
            return schedules

        except Exception as e:
            self.logger.error(f"Failed to load schedules: {e}")
            return {}

    def save_jobs(self, jobs: dict[str, ScanJob], max_jobs: int = 1000) -> bool:
        """Save job history to disk.

        Args:
            jobs: Dictionary of jobs
            max_jobs: Maximum number of jobs to retain

        Returns:
            True if successful
        """
        try:
            # Keep only most recent jobs
            sorted_jobs = sorted(
                jobs.values(),
                key=lambda j: j.started_at,
                reverse=True
            )[:max_jobs]

            data = []
            for job in sorted_jobs:
                job_data = {
                    "id": job.id,
                    "schedule_id": job.schedule_id,
                    "target": job.target,
                    "started_at": job.started_at.isoformat(),
                    "completed_at": job.completed_at.isoformat() if job.completed_at else None,
                    "status": job.status,
                    "error": job.error,
                    "findings_count": job.findings_count,
                }
                data.append(job_data)

            self.jobs_file.write_text(json.dumps(data, indent=2))
            self.logger.debug(f"Saved {len(data)} job records")
            return True

        except Exception as e:
            self.logger.error(f"Failed to save jobs: {e}")
            return False

    def load_jobs(self) -> dict[str, ScanJob]:
        """Load job history from disk.

        Returns:
            Dictionary of jobs
        """
        if not self.jobs_file.exists():
            return {}

        try:
            data = json.loads(self.jobs_file.read_text())
            jobs = {}

            for job_data in data:
                try:
                    job = ScanJob(
                        id=job_data["id"],
                        schedule_id=job_data["schedule_id"],
                        target=job_data["target"],
                        started_at=datetime.fromisoformat(job_data["started_at"]),
                        completed_at=datetime.fromisoformat(job_data["completed_at"]) if job_data.get("completed_at") else None,
                        status=job_data.get("status", "unknown"),
                        error=job_data.get("error"),
                        findings_count=job_data.get("findings_count", 0),
                    )
                    jobs[job.id] = job
                except Exception as e:
                    self.logger.warning(f"Failed to load job: {e}")

            self.logger.info(f"Loaded {len(jobs)} job records")
            return jobs

        except Exception as e:
            self.logger.error(f"Failed to load jobs: {e}")
            return {}

    def attach_to_scheduler(self, scheduler: ScanScheduler) -> None:
        """Attach storage to scheduler and load existing data.

        Args:
            scheduler: Scheduler instance
        """
        # Load existing data
        scheduler.schedules = self.load_schedules()
        scheduler.jobs = self.load_jobs()

        self.logger.info(
            f"Attached storage: {len(scheduler.schedules)} schedules, "
            f"{len(scheduler.jobs)} jobs"
        )

    def sync_from_scheduler(self, scheduler: ScanScheduler) -> None:
        """Save scheduler state to storage.

        Args:
            scheduler: Scheduler instance
        """
        self.save_schedules(scheduler.schedules)
        self.save_jobs(scheduler.jobs)

    def clear_jobs(self, older_than_days: int = 30) -> int:
        """Clear old job records.

        Args:
            older_than_days: Remove jobs older than this many days

        Returns:
            Number of jobs removed
        """
        if not self.jobs_file.exists():
            return 0

        try:
            data = json.loads(self.jobs_file.read_text())
            cutoff = datetime.now().timestamp() - (older_than_days * 86400)

            original_count = len(data)
            data = [
                j for j in data
                if datetime.fromisoformat(j["started_at"]).timestamp() > cutoff
            ]

            self.jobs_file.write_text(json.dumps(data, indent=2))
            removed = original_count - len(data)

            self.logger.info(f"Cleared {removed} old job records")
            return removed

        except Exception as e:
            self.logger.error(f"Failed to clear old jobs: {e}")
            return 0

    def export_report(self, output_path: Path) -> bool:
        """Export scheduler data as a report.

        Args:
            output_path: Path for output file

        Returns:
            True if successful
        """
        try:
            schedules = self.load_schedules()
            jobs = self.load_jobs()

            report = {
                "generated_at": datetime.now().isoformat(),
                "summary": {
                    "total_schedules": len(schedules),
                    "enabled_schedules": len([s for s in schedules.values() if s.enabled]),
                    "total_jobs": len(jobs),
                    "completed_jobs": len([j for j in jobs.values() if j.status == "completed"]),
                    "failed_jobs": len([j for j in jobs.values() if j.status == "failed"]),
                    "total_findings": sum(j.findings_count for j in jobs.values()),
                },
                "schedules": [s.to_dict() for s in schedules.values()],
                "recent_jobs": [
                    {
                        "id": j.id,
                        "schedule_id": j.schedule_id,
                        "target": j.target,
                        "started_at": j.started_at.isoformat(),
                        "status": j.status,
                        "findings_count": j.findings_count,
                    }
                    for j in sorted(jobs.values(), key=lambda x: x.started_at, reverse=True)[:100]
                ],
            }

            output_path.write_text(json.dumps(report, indent=2))
            self.logger.info(f"Exported report to {output_path}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to export report: {e}")
            return False
