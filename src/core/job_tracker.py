"""
Database-backed job tracker for background scan operations.
"""
from datetime import datetime
from typing import Any

from sqlalchemy import desc
from sqlalchemy.orm import Session

from src.db.connection import get_db_session
from src.db.models import ScanJob


class JobTracker:
    """Database-backed job tracker for background scan operations."""

    def create_job(self, job_type: str, total_targets: int, metadata: dict[str, Any] | None = None) -> ScanJob:
        """Create a new scan job."""
        with get_db_session() as session:
            job = ScanJob(
                job_type=job_type,
                status="pending",
                total_targets=total_targets,
                metadata_=metadata or {},
            )
            session.add(job)
            session.commit()
            session.refresh(job)
            # Return a detached copy with the ID
            return self._detach_job(job)

    def start_job(self, job_id: str) -> None:
        """Mark a job as running."""
        with get_db_session() as session:
            job = session.get(ScanJob, job_id)
            if job:
                job.status = "running"
                job.started_at = datetime.utcnow()
                session.commit()

    def update_progress(self, job_id: str, success: bool) -> None:
        """Update job progress after a single scan completes."""
        with get_db_session() as session:
            job = session.get(ScanJob, job_id)
            if job:
                job.completed_count += 1
                if success:
                    job.success_count += 1
                else:
                    job.fail_count += 1
                session.commit()

    def complete_job(self, job_id: str, error: str | None = None) -> None:
        """Mark a job as completed."""
        with get_db_session() as session:
            job = session.get(ScanJob, job_id)
            if job:
                job.status = "failed" if error else "completed"
                job.completed_at = datetime.utcnow()
                job.error_message = error
                session.commit()

    def get_job(self, job_id: str) -> ScanJob | None:
        """Get a job by ID."""
        with get_db_session() as session:
            job = session.get(ScanJob, job_id)
            if job:
                return self._detach_job(job)
            return None

    def get_active_jobs(self) -> list[ScanJob]:
        """Get all running jobs."""
        with get_db_session() as session:
            jobs = session.query(ScanJob).filter(
                ScanJob.status == "running"
            ).order_by(desc(ScanJob.started_at)).all()
            return [self._detach_job(j) for j in jobs]

    def get_recent_jobs(self, limit: int = 10) -> list[ScanJob]:
        """Get recent jobs (running first, then by created_at)."""
        with get_db_session() as session:
            # Get running jobs first
            running = session.query(ScanJob).filter(
                ScanJob.status == "running"
            ).order_by(desc(ScanJob.started_at)).all()

            # Then get non-running jobs
            remaining_limit = limit - len(running)
            if remaining_limit > 0:
                other = session.query(ScanJob).filter(
                    ScanJob.status != "running"
                ).order_by(desc(ScanJob.created_at)).limit(remaining_limit).all()
            else:
                other = []

            return [self._detach_job(j) for j in running + other]

    def _detach_job(self, job: ScanJob) -> ScanJob:
        """Create a detached copy of a job that can be used outside the session."""
        # Create a new instance with the same data
        detached = ScanJob(
            id=job.id,
            job_type=job.job_type,
            status=job.status,
            total_targets=job.total_targets,
            completed_count=job.completed_count,
            success_count=job.success_count,
            fail_count=job.fail_count,
            error_message=job.error_message,
            metadata_=job.metadata_,
            created_at=job.created_at,
            started_at=job.started_at,
            completed_at=job.completed_at,
        )
        return detached


# Singleton instance
_job_tracker: JobTracker | None = None


def get_job_tracker() -> JobTracker:
    """Get the job tracker instance."""
    global _job_tracker
    if _job_tracker is None:
        _job_tracker = JobTracker()
    return _job_tracker
