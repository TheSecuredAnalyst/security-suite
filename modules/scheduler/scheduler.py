"""Scan scheduler for recurring security assessments."""

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from core.logger import get_logger
from core.models import ScanResult


class ScheduleFrequency(str, Enum):
    """Scan frequency options."""
    ONCE = "once"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"  # Cron expression


@dataclass
class ScheduledScan:
    """Scheduled scan configuration."""
    id: str
    name: str
    target: str
    modules: list[str]
    frequency: ScheduleFrequency
    cron_expression: str | None = None  # For custom frequency
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    last_run: datetime | None = None
    next_run: datetime | None = None
    run_count: int = 0
    notify_webhook: str | None = None
    notify_on_findings: bool = True
    siem_export: bool = False
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "target": self.target,
            "modules": self.modules,
            "frequency": self.frequency.value,
            "cron_expression": self.cron_expression,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat(),
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "run_count": self.run_count,
            "notify_webhook": self.notify_webhook,
            "notify_on_findings": self.notify_on_findings,
            "siem_export": self.siem_export,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScheduledScan":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            target=data["target"],
            modules=data["modules"],
            frequency=ScheduleFrequency(data["frequency"]),
            cron_expression=data.get("cron_expression"),
            enabled=data.get("enabled", True),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            last_run=datetime.fromisoformat(data["last_run"]) if data.get("last_run") else None,
            next_run=datetime.fromisoformat(data["next_run"]) if data.get("next_run") else None,
            run_count=data.get("run_count", 0),
            notify_webhook=data.get("notify_webhook"),
            notify_on_findings=data.get("notify_on_findings", True),
            siem_export=data.get("siem_export", False),
            tags=data.get("tags", []),
        )


@dataclass
class ScanJob:
    """A running or completed scan job."""
    id: str
    schedule_id: str
    target: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"  # running, completed, failed
    results: list[ScanResult] = field(default_factory=list)
    error: str | None = None
    findings_count: int = 0


class ScanScheduler:
    """Scheduler for recurring security scans."""

    def __init__(self, storage_path: str | None = None):
        """Initialize scheduler.

        Args:
            storage_path: Path to store schedule data
        """
        self.logger = get_logger("scheduler")
        self.schedules: dict[str, ScheduledScan] = {}
        self.jobs: dict[str, ScanJob] = {}
        self._running = False
        self._task: asyncio.Task | None = None
        self._scan_callback: Callable | None = None
        self._notify_callback: Callable | None = None
        self._storage_path = storage_path

    def set_scan_callback(
        self, callback: Callable[[str, list[str]], Awaitable[list[ScanResult]]]
    ) -> None:
        """Set callback for running scans.

        Args:
            callback: Async function that takes (target, modules) and returns results
        """
        self._scan_callback = callback

    def set_notify_callback(
        self, callback: Callable[[ScheduledScan, ScanJob], Awaitable[None]]
    ) -> None:
        """Set callback for notifications.

        Args:
            callback: Async function for sending notifications
        """
        self._notify_callback = callback

    def create_schedule(
        self,
        name: str,
        target: str,
        modules: list[str],
        frequency: ScheduleFrequency,
        cron_expression: str | None = None,
        notify_webhook: str | None = None,
        tags: list[str] | None = None,
    ) -> ScheduledScan:
        """Create a new scheduled scan.

        Args:
            name: Schedule name
            target: Target to scan
            modules: List of scan modules to run
            frequency: Scan frequency
            cron_expression: Cron expression for custom frequency
            notify_webhook: Webhook URL for notifications
            tags: Tags for categorization

        Returns:
            Created schedule
        """
        schedule_id = str(uuid.uuid4())[:8]

        schedule = ScheduledScan(
            id=schedule_id,
            name=name,
            target=target,
            modules=modules,
            frequency=frequency,
            cron_expression=cron_expression,
            notify_webhook=notify_webhook,
            tags=tags or [],
        )

        # Calculate next run time
        schedule.next_run = self._calculate_next_run(schedule)

        self.schedules[schedule_id] = schedule
        self.logger.info(f"Created schedule '{name}' ({schedule_id})")

        return schedule

    def get_schedule(self, schedule_id: str) -> ScheduledScan | None:
        """Get schedule by ID."""
        return self.schedules.get(schedule_id)

    def list_schedules(self, enabled_only: bool = False) -> list[ScheduledScan]:
        """List all schedules."""
        schedules = list(self.schedules.values())
        if enabled_only:
            schedules = [s for s in schedules if s.enabled]
        return sorted(schedules, key=lambda s: s.next_run or datetime.max)

    def update_schedule(self, schedule_id: str, **kwargs) -> ScheduledScan | None:
        """Update schedule properties."""
        schedule = self.schedules.get(schedule_id)
        if not schedule:
            return None

        for key, value in kwargs.items():
            if hasattr(schedule, key):
                setattr(schedule, key, value)

        # Recalculate next run if frequency changed
        if "frequency" in kwargs or "cron_expression" in kwargs:
            schedule.next_run = self._calculate_next_run(schedule)

        self.logger.info(f"Updated schedule {schedule_id}")
        return schedule

    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule."""
        if schedule_id in self.schedules:
            del self.schedules[schedule_id]
            self.logger.info(f"Deleted schedule {schedule_id}")
            return True
        return False

    def enable_schedule(self, schedule_id: str) -> bool:
        """Enable a schedule."""
        schedule = self.schedules.get(schedule_id)
        if schedule:
            schedule.enabled = True
            schedule.next_run = self._calculate_next_run(schedule)
            return True
        return False

    def disable_schedule(self, schedule_id: str) -> bool:
        """Disable a schedule."""
        schedule = self.schedules.get(schedule_id)
        if schedule:
            schedule.enabled = False
            return True
        return False

    async def run_now(self, schedule_id: str) -> ScanJob | None:
        """Run a scheduled scan immediately.

        Args:
            schedule_id: Schedule ID to run

        Returns:
            ScanJob if started, None if schedule not found
        """
        schedule = self.schedules.get(schedule_id)
        if not schedule:
            return None

        return await self._run_scan(schedule)

    async def start(self) -> None:
        """Start the scheduler background task."""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._scheduler_loop())
        self.logger.info("Scheduler started")

    async def stop(self) -> None:
        """Stop the scheduler."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self.logger.info("Scheduler stopped")

    async def _scheduler_loop(self) -> None:
        """Main scheduler loop."""
        while self._running:
            try:
                now = datetime.now()

                # Check each schedule
                for schedule in self.schedules.values():
                    if not schedule.enabled:
                        continue

                    if schedule.next_run and schedule.next_run <= now:
                        # Time to run this scan
                        self.logger.info(f"Running scheduled scan: {schedule.name}")
                        await self._run_scan(schedule)

                        # Update next run time
                        schedule.next_run = self._calculate_next_run(schedule)

                # Sleep for a minute before checking again
                await asyncio.sleep(60)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Scheduler error: {e}")
                await asyncio.sleep(60)

    async def _run_scan(self, schedule: ScheduledScan) -> ScanJob:
        """Run a scan for a schedule."""
        job_id = str(uuid.uuid4())[:8]

        job = ScanJob(
            id=job_id,
            schedule_id=schedule.id,
            target=schedule.target,
            started_at=datetime.now(),
        )

        self.jobs[job_id] = job

        try:
            if self._scan_callback:
                results = await self._scan_callback(schedule.target, schedule.modules)
                job.results = results
                job.findings_count = sum(len(r.findings) for r in results)
                job.status = "completed"
            else:
                job.status = "failed"
                job.error = "No scan callback configured"

            job.completed_at = datetime.now()

            # Update schedule stats
            schedule.last_run = job.started_at
            schedule.run_count += 1

            # Send notifications if configured
            if self._notify_callback and schedule.notify_on_findings:
                if job.findings_count > 0 or not schedule.notify_on_findings:
                    await self._notify_callback(schedule, job)

        except Exception as e:
            job.status = "failed"
            job.error = str(e)
            job.completed_at = datetime.now()
            self.logger.error(f"Scan failed for {schedule.name}: {e}")

        return job

    def _calculate_next_run(self, schedule: ScheduledScan) -> datetime:
        """Calculate next run time for a schedule."""
        now = datetime.now()

        if schedule.frequency == ScheduleFrequency.ONCE:
            # One-time scan, run now if never run
            if not schedule.last_run:
                return now
            return datetime.max  # Never run again

        elif schedule.frequency == ScheduleFrequency.HOURLY:
            next_run = now + timedelta(hours=1)
            return next_run.replace(minute=0, second=0, microsecond=0)

        elif schedule.frequency == ScheduleFrequency.DAILY:
            next_run = now + timedelta(days=1)
            return next_run.replace(hour=2, minute=0, second=0, microsecond=0)  # 2 AM

        elif schedule.frequency == ScheduleFrequency.WEEKLY:
            days_until_monday = (7 - now.weekday()) % 7 or 7
            next_run = now + timedelta(days=days_until_monday)
            return next_run.replace(hour=2, minute=0, second=0, microsecond=0)

        elif schedule.frequency == ScheduleFrequency.MONTHLY:
            if now.month == 12:
                next_run = now.replace(year=now.year + 1, month=1, day=1)
            else:
                next_run = now.replace(month=now.month + 1, day=1)
            return next_run.replace(hour=2, minute=0, second=0, microsecond=0)

        elif schedule.frequency == ScheduleFrequency.CUSTOM and schedule.cron_expression:
            return self._parse_cron(schedule.cron_expression)

        return now + timedelta(days=1)

    def _parse_cron(self, expression: str) -> datetime:
        """Parse simple cron expression and return next run time.

        Supports: minute hour day month weekday
        """
        parts = expression.split()
        if len(parts) != 5:
            return datetime.now() + timedelta(days=1)

        minute, hour, day, month, weekday = parts
        now = datetime.now()

        # Simple implementation - just handle basic cases
        try:
            target_minute = int(minute) if minute != "*" else now.minute
            target_hour = int(hour) if hour != "*" else now.hour

            next_run = now.replace(
                hour=target_hour,
                minute=target_minute,
                second=0,
                microsecond=0
            )

            if next_run <= now:
                next_run += timedelta(days=1)

            return next_run

        except ValueError:
            return now + timedelta(days=1)

    def get_job(self, job_id: str) -> ScanJob | None:
        """Get job by ID."""
        return self.jobs.get(job_id)

    def list_jobs(
        self,
        schedule_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[ScanJob]:
        """List scan jobs."""
        jobs = list(self.jobs.values())

        if schedule_id:
            jobs = [j for j in jobs if j.schedule_id == schedule_id]

        if status:
            jobs = [j for j in jobs if j.status == status]

        # Sort by start time, newest first
        jobs.sort(key=lambda j: j.started_at, reverse=True)

        return jobs[:limit]

    def get_stats(self) -> dict:
        """Get scheduler statistics."""
        total_schedules = len(self.schedules)
        enabled_schedules = len([s for s in self.schedules.values() if s.enabled])
        total_jobs = len(self.jobs)
        completed_jobs = len([j for j in self.jobs.values() if j.status == "completed"])
        failed_jobs = len([j for j in self.jobs.values() if j.status == "failed"])
        total_findings = sum(j.findings_count for j in self.jobs.values())

        return {
            "total_schedules": total_schedules,
            "enabled_schedules": enabled_schedules,
            "total_jobs": total_jobs,
            "completed_jobs": completed_jobs,
            "failed_jobs": failed_jobs,
            "total_findings": total_findings,
            "scheduler_running": self._running,
        }
