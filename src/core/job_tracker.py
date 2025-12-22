"""
Simple in-memory job tracker for background scan operations.
"""
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
import uuid


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ScanJob:
    """Represents a background scan job."""

    id: str
    job_type: str  # 'batch', 'refresh_all'
    status: JobStatus = JobStatus.PENDING
    total_targets: int = 0
    completed_count: int = 0
    success_count: int = 0
    fail_count: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def progress_percent(self) -> int:
        if self.total_targets == 0:
            return 0
        return int((self.completed_count / self.total_targets) * 100)

    @property
    def is_running(self) -> bool:
        return self.status == JobStatus.RUNNING

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "job_type": self.job_type,
            "status": self.status.value,
            "total_targets": self.total_targets,
            "completed_count": self.completed_count,
            "success_count": self.success_count,
            "fail_count": self.fail_count,
            "progress_percent": self.progress_percent,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
            "metadata": self.metadata,
        }


class JobTracker:
    """Thread-safe job tracker for background scan operations."""

    _instance: "JobTracker | None" = None
    _lock = threading.Lock()

    def __new__(cls) -> "JobTracker":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._jobs: dict[str, ScanJob] = {}
                    cls._instance._job_lock = threading.Lock()
        return cls._instance

    def create_job(self, job_type: str, total_targets: int, metadata: dict[str, Any] | None = None) -> ScanJob:
        """Create a new scan job."""
        job = ScanJob(
            id=str(uuid.uuid4())[:8],
            job_type=job_type,
            total_targets=total_targets,
            metadata=metadata or {},
        )
        with self._job_lock:
            self._jobs[job.id] = job
        return job

    def start_job(self, job_id: str) -> None:
        """Mark a job as running."""
        with self._job_lock:
            if job_id in self._jobs:
                self._jobs[job_id].status = JobStatus.RUNNING
                self._jobs[job_id].started_at = datetime.now()

    def update_progress(self, job_id: str, success: bool) -> None:
        """Update job progress after a single scan completes."""
        with self._job_lock:
            if job_id in self._jobs:
                job = self._jobs[job_id]
                job.completed_count += 1
                if success:
                    job.success_count += 1
                else:
                    job.fail_count += 1

    def complete_job(self, job_id: str, error: str | None = None) -> None:
        """Mark a job as completed."""
        with self._job_lock:
            if job_id in self._jobs:
                job = self._jobs[job_id]
                job.status = JobStatus.FAILED if error else JobStatus.COMPLETED
                job.completed_at = datetime.now()
                job.error = error

    def get_job(self, job_id: str) -> ScanJob | None:
        """Get a job by ID."""
        with self._job_lock:
            return self._jobs.get(job_id)

    def get_active_jobs(self) -> list[ScanJob]:
        """Get all running jobs."""
        with self._job_lock:
            return [j for j in self._jobs.values() if j.status == JobStatus.RUNNING]

    def get_recent_jobs(self, limit: int = 10) -> list[ScanJob]:
        """Get recent jobs (running first, then by start time)."""
        with self._job_lock:
            jobs = list(self._jobs.values())
            # Sort: running first, then by started_at descending
            jobs.sort(key=lambda j: (
                0 if j.status == JobStatus.RUNNING else 1,
                -(j.started_at.timestamp() if j.started_at else 0)
            ))
            return jobs[:limit]

    def cleanup_old_jobs(self, keep_count: int = 20) -> None:
        """Remove old completed jobs, keeping the most recent ones."""
        with self._job_lock:
            completed = [j for j in self._jobs.values() if j.status in (JobStatus.COMPLETED, JobStatus.FAILED)]
            completed.sort(key=lambda j: j.completed_at or datetime.min, reverse=True)
            for job in completed[keep_count:]:
                del self._jobs[job.id]


def get_job_tracker() -> JobTracker:
    """Get the singleton job tracker instance."""
    return JobTracker()
