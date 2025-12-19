"""
APScheduler-based scheduler for automated device rescanning.
"""
import asyncio
import logging
from datetime import datetime
from typing import Any

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from src.config.settings import get_settings
from src.core.scanner import DeviceScanner
from src.credentials.local import LocalCredentialProvider
from src.db.connection import get_db_session
from src.db.repositories.device import DeviceRepository

logger = logging.getLogger(__name__)

# Global scheduler instance
_scheduler: "DeviceRescanScheduler | None" = None


class DeviceRescanScheduler:
    """Manages scheduled rescanning of network devices."""

    def __init__(self):
        self.scheduler = BackgroundScheduler(
            job_defaults={
                "coalesce": True,  # Combine missed runs into one
                "max_instances": 1,  # Only one instance of job at a time
                "misfire_grace_time": 3600,  # Allow 1 hour grace for missed jobs
            }
        )
        self._is_running = False
        self._last_run: datetime | None = None
        self._last_run_results: dict[str, Any] = {}

    def start(self) -> None:
        """Start the scheduler."""
        if self._is_running:
            logger.warning("Scheduler already running")
            return

        settings = get_settings()

        if not settings.rescan_enabled:
            logger.info("Scheduled rescanning is disabled")
            return

        # Add the rescan job
        self.scheduler.add_job(
            self._run_rescan,
            trigger=IntervalTrigger(hours=settings.rescan_interval_hours),
            id="device_rescan",
            name="Device Rescan Job",
            replace_existing=True,
        )

        self.scheduler.start()
        self._is_running = True
        logger.info(
            f"Scheduler started. Rescanning every {settings.rescan_interval_hours} hours"
        )

    def stop(self) -> None:
        """Stop the scheduler."""
        if self._is_running:
            self.scheduler.shutdown(wait=False)
            self._is_running = False
            logger.info("Scheduler stopped")

    def is_running(self) -> bool:
        """Check if scheduler is running."""
        return self._is_running

    def get_status(self) -> dict[str, Any]:
        """Get scheduler status information."""
        settings = get_settings()
        next_run = None

        if self._is_running:
            job = self.scheduler.get_job("device_rescan")
            if job and job.next_run_time:
                next_run = job.next_run_time.isoformat()

        return {
            "enabled": settings.rescan_enabled,
            "running": self._is_running,
            "interval_hours": settings.rescan_interval_hours,
            "max_concurrent": settings.rescan_max_concurrent,
            "next_run": next_run,
            "last_run": self._last_run.isoformat() if self._last_run else None,
            "last_run_results": self._last_run_results,
        }

    def trigger_now(self) -> None:
        """Trigger an immediate rescan (outside of schedule)."""
        if not self._is_running:
            logger.warning("Scheduler not running, starting one-time rescan")
        self._run_rescan()

    def update_schedule(self, interval_hours: int) -> None:
        """Update the rescan interval."""
        if self._is_running:
            self.scheduler.reschedule_job(
                "device_rescan",
                trigger=IntervalTrigger(hours=interval_hours),
            )
            logger.info(f"Rescan schedule updated to every {interval_hours} hours")

    def _run_rescan(self) -> None:
        """Execute the rescan of all active devices."""
        logger.info("Starting scheduled device rescan")
        self._last_run = datetime.utcnow()

        settings = get_settings()
        results = {
            "started_at": self._last_run.isoformat(),
            "total_devices": 0,
            "successful": 0,
            "failed": 0,
            "skipped": 0,
            "errors": [],
        }

        try:
            # Get all active devices
            with get_db_session() as session:
                device_repo = DeviceRepository(session)
                devices = device_repo.get_all(is_active=True, limit=1000)
                results["total_devices"] = len(devices)

                # Extract device info while session is open
                device_list = [
                    {
                        "id": str(d.id),
                        "ip_address": d.ip_address,
                        "credential_profile_name": d.credential_profile_name,
                    }
                    for d in devices
                ]

            if not device_list:
                logger.info("No active devices to rescan")
                results["completed_at"] = datetime.utcnow().isoformat()
                self._last_run_results = results
                return

            # Get credential provider
            cred_provider = LocalCredentialProvider(settings.credential_path)

            # Run async rescan with concurrency control
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                scan_results = loop.run_until_complete(
                    self._rescan_devices(
                        device_list,
                        cred_provider,
                        settings.rescan_max_concurrent,
                    )
                )
            finally:
                loop.close()

            # Aggregate results
            for device_id, result in scan_results.items():
                if result.get("status") == "success":
                    results["successful"] += 1
                elif result.get("status") == "skipped":
                    results["skipped"] += 1
                else:
                    results["failed"] += 1
                    if result.get("error"):
                        results["errors"].append(
                            {"device_id": device_id, "error": result["error"]}
                        )

            results["completed_at"] = datetime.utcnow().isoformat()
            logger.info(
                f"Rescan completed: {results['successful']} success, "
                f"{results['failed']} failed, {results['skipped']} skipped"
            )

        except Exception as e:
            logger.exception(f"Error during scheduled rescan: {e}")
            results["error"] = str(e)
            results["completed_at"] = datetime.utcnow().isoformat()

        self._last_run_results = results

    async def _rescan_devices(
        self,
        devices: list[dict],
        cred_provider: LocalCredentialProvider,
        max_concurrent: int,
    ) -> dict[str, dict]:
        """Rescan multiple devices with concurrency control."""
        semaphore = asyncio.Semaphore(max_concurrent)
        results = {}

        async def rescan_one(device: dict) -> tuple[str, dict]:
            async with semaphore:
                device_id = device["id"]
                ip_address = device["ip_address"]
                profile_name = device["credential_profile_name"]

                # Skip if no credential profile associated
                if not profile_name:
                    return device_id, {"status": "skipped", "reason": "no_credentials"}

                try:
                    # Get the credential profile
                    profile = await cred_provider.get_profile(profile_name)
                    if not profile:
                        return device_id, {
                            "status": "skipped",
                            "reason": "profile_not_found",
                        }

                    # Scan the device
                    scanner = DeviceScanner()
                    result = await scanner.scan_device(
                        ip_address=ip_address,
                        credential=profile.to_snmp_credential(),
                        scan_type="scheduled",
                        save_to_db=True,
                        credential_profile_name=profile_name,
                    )

                    if result.success:
                        return device_id, {"status": "success"}
                    else:
                        return device_id, {"status": "failed", "error": result.error}

                except Exception as e:
                    logger.error(f"Error rescanning {ip_address}: {e}")
                    return device_id, {"status": "failed", "error": str(e)}

        # Run all rescans concurrently
        tasks = [rescan_one(device) for device in devices]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for item in completed:
            if isinstance(item, Exception):
                logger.error(f"Task exception: {item}")
            else:
                device_id, result = item
                results[device_id] = result

        return results


def get_scheduler() -> DeviceRescanScheduler:
    """Get or create the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = DeviceRescanScheduler()
    return _scheduler
