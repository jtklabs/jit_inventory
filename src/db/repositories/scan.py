"""
Scan history repository for database operations.
"""
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.db.models import ScanHistory


class ScanHistoryRepository:
    """Repository for ScanHistory CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_id(self, scan_id: str) -> ScanHistory | None:
        """Get scan by ID."""
        return self.session.get(ScanHistory, scan_id)

    def get_by_device(self, device_id: str, limit: int = 50) -> list[ScanHistory]:
        """Get scan history for a specific device."""
        stmt = (
            select(ScanHistory)
            .where(ScanHistory.device_id == device_id)
            .order_by(ScanHistory.started_at.desc())
            .limit(limit)
        )
        return list(self.session.execute(stmt).scalars().all())

    def get_by_ip(self, ip_address: str, limit: int = 50) -> list[ScanHistory]:
        """Get scan history for a specific IP."""
        stmt = (
            select(ScanHistory)
            .where(ScanHistory.ip_address == ip_address)
            .order_by(ScanHistory.started_at.desc())
            .limit(limit)
        )
        return list(self.session.execute(stmt).scalars().all())

    def get_recent(
        self,
        limit: int = 100,
        offset: int = 0,
        status: str | None = None,
        scan_type: str | None = None,
    ) -> list[ScanHistory]:
        """Get recent scan history."""
        stmt = select(ScanHistory)

        if status:
            stmt = stmt.where(ScanHistory.scan_status == status)
        if scan_type:
            stmt = stmt.where(ScanHistory.scan_type == scan_type)

        stmt = stmt.order_by(ScanHistory.started_at.desc()).offset(offset).limit(limit)
        return list(self.session.execute(stmt).scalars().all())

    def create(
        self,
        ip_address: str,
        scan_type: str,
        scan_status: str,
        device_id: str | None = None,
        hostname: str | None = None,
        vendor: str | None = None,
        device_type: str | None = None,
        platform: str | None = None,
        model: str | None = None,
        serial_number: str | None = None,
        software_version: str | None = None,
        sys_object_id: str | None = None,
        sys_description: str | None = None,
        raw_snmp_data: dict | None = None,
        error_message: str | None = None,
        duration_ms: int | None = None,
        credential_profile_name: str | None = None,
        snmp_version: str | None = None,
    ) -> ScanHistory:
        """Create a new scan history record."""
        scan = ScanHistory(
            ip_address=ip_address,
            scan_type=scan_type,
            scan_status=scan_status,
            device_id=device_id,
            hostname=hostname,
            vendor=vendor,
            device_type=device_type,
            platform=platform,
            model=model,
            serial_number=serial_number,
            software_version=software_version,
            sys_object_id=sys_object_id,
            sys_description=sys_description,
            raw_snmp_data=raw_snmp_data,
            error_message=error_message,
            duration_ms=duration_ms,
            credential_profile_name=credential_profile_name,
            snmp_version=snmp_version,
            completed_at=datetime.utcnow() if scan_status in ("success", "failed") else None,
        )
        self.session.add(scan)
        self.session.flush()
        return scan

    def count(self, status: str | None = None, scan_type: str | None = None) -> int:
        """Count scan history records."""
        stmt = select(ScanHistory)

        if status:
            stmt = stmt.where(ScanHistory.scan_status == status)
        if scan_type:
            stmt = stmt.where(ScanHistory.scan_type == scan_type)

        return len(list(self.session.execute(stmt).scalars().all()))

    def get_stats(self) -> dict:
        """Get scan statistics."""
        total = self.count()
        success = self.count(status="success")
        failed = self.count(status="failed")

        return {
            "total": total,
            "success": success,
            "failed": failed,
            "success_rate": (success / total * 100) if total > 0 else 0,
        }
