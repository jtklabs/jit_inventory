"""
Repository for Nautobot sync status operations.
"""
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.db.models import Device, NautobotSyncStatus


class NautobotSyncRepository:
    """Repository for NautobotSyncStatus CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_device_id(self, device_id: str) -> NautobotSyncStatus | None:
        """Get sync status by device ID."""
        stmt = select(NautobotSyncStatus).where(NautobotSyncStatus.device_id == device_id)
        return self.session.execute(stmt).scalar_one_or_none()

    def create_or_update(
        self,
        device_id: str,
        sync_status: str,
        nautobot_device_id: str | None = None,
        nautobot_ip_id: str | None = None,
        nautobot_prefix_id: str | None = None,
        error_message: str | None = None,
    ) -> NautobotSyncStatus:
        """Create or update sync status for a device."""
        status = self.get_by_device_id(device_id)

        if status is None:
            status = NautobotSyncStatus(device_id=device_id)
            self.session.add(status)

        status.sync_status = sync_status

        if nautobot_device_id is not None:
            status.nautobot_device_id = nautobot_device_id
        if nautobot_ip_id is not None:
            status.nautobot_ip_id = nautobot_ip_id
        if nautobot_prefix_id is not None:
            status.nautobot_prefix_id = nautobot_prefix_id
        if error_message is not None:
            status.error_message = error_message

        if sync_status == "synced":
            status.last_synced_at = datetime.utcnow()

        self.session.flush()
        return status

    def mark_synced(
        self,
        device_id: str,
        nautobot_device_id: str,
        nautobot_ip_id: str | None = None,
    ) -> NautobotSyncStatus:
        """Mark a device as synced."""
        return self.create_or_update(
            device_id=device_id,
            sync_status="synced",
            nautobot_device_id=nautobot_device_id,
            nautobot_ip_id=nautobot_ip_id,
            error_message=None,
        )

    def mark_failed(
        self,
        device_id: str,
        error: str,
    ) -> NautobotSyncStatus:
        """Mark a sync as failed."""
        return self.create_or_update(
            device_id=device_id,
            sync_status="failed",
            error_message=error,
        )

    def mark_no_prefix(
        self,
        device_id: str,
    ) -> NautobotSyncStatus:
        """Mark a device as having no prefix in Nautobot."""
        return self.create_or_update(
            device_id=device_id,
            sync_status="no_prefix",
            error_message=None,
        )

    def mark_no_location(
        self,
        device_id: str,
        prefix_id: str | None = None,
    ) -> NautobotSyncStatus:
        """Mark a device as having a prefix but no location."""
        return self.create_or_update(
            device_id=device_id,
            sync_status="no_location",
            nautobot_prefix_id=prefix_id,
            error_message=None,
        )

    def mark_ready(
        self,
        device_id: str,
        prefix_id: str | None = None,
    ) -> NautobotSyncStatus:
        """Mark a device as ready to sync (has location)."""
        return self.create_or_update(
            device_id=device_id,
            sync_status="ready",
            nautobot_prefix_id=prefix_id,
            error_message=None,
        )

    def get_devices_by_status(
        self,
        status: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Device]:
        """Get devices with a specific sync status."""
        stmt = (
            select(Device)
            .join(NautobotSyncStatus)
            .where(NautobotSyncStatus.sync_status == status)
            .offset(offset)
            .limit(limit)
        )
        return list(self.session.execute(stmt).scalars().all())

    def get_devices_without_sync_status(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Device]:
        """Get devices that don't have a sync status record yet."""
        subquery = select(NautobotSyncStatus.device_id)
        stmt = (
            select(Device)
            .where(Device.id.notin_(subquery))
            .offset(offset)
            .limit(limit)
        )
        return list(self.session.execute(stmt).scalars().all())

    def count_by_status(self) -> dict[str, int]:
        """Count devices by sync status."""
        # Get all statuses
        stmt = select(NautobotSyncStatus.sync_status)
        statuses = self.session.execute(stmt).scalars().all()

        counts = {
            "pending": 0,
            "no_prefix": 0,
            "no_location": 0,
            "ready": 0,
            "synced": 0,
            "failed": 0,
        }

        for status in statuses:
            if status in counts:
                counts[status] += 1

        # Count devices without any sync status as pending
        subquery = select(NautobotSyncStatus.device_id)
        stmt = select(Device).where(Device.id.notin_(subquery))
        no_status_count = len(list(self.session.execute(stmt).scalars().all()))
        counts["pending"] += no_status_count

        return counts

    def delete_by_device_id(self, device_id: str) -> bool:
        """Delete sync status for a device."""
        status = self.get_by_device_id(device_id)
        if status:
            self.session.delete(status)
            self.session.flush()
            return True
        return False
