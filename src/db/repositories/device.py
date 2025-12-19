"""
Device repository for database operations.
"""
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.db.models import Device


class DeviceRepository:
    """Repository for Device CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_id(self, device_id: str) -> Device | None:
        """Get device by ID."""
        return self.session.get(Device, device_id)

    def get_by_ip(self, ip_address: str) -> Device | None:
        """Get device by IP address."""
        stmt = select(Device).where(Device.ip_address == ip_address)
        return self.session.execute(stmt).scalar_one_or_none()

    def get_all(
        self,
        vendor: str | None = None,
        device_type: str | None = None,
        is_active: bool | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Device]:
        """Get all devices with optional filtering."""
        stmt = select(Device)

        if vendor:
            stmt = stmt.where(Device.vendor == vendor)
        if device_type:
            stmt = stmt.where(Device.device_type == device_type)
        if is_active is not None:
            stmt = stmt.where(Device.is_active == is_active)

        stmt = stmt.order_by(Device.last_seen.desc()).offset(offset).limit(limit)
        return list(self.session.execute(stmt).scalars().all())

    def count(
        self,
        vendor: str | None = None,
        device_type: str | None = None,
        is_active: bool | None = None,
    ) -> int:
        """Count devices with optional filtering."""
        stmt = select(Device)

        if vendor:
            stmt = stmt.where(Device.vendor == vendor)
        if device_type:
            stmt = stmt.where(Device.device_type == device_type)
        if is_active is not None:
            stmt = stmt.where(Device.is_active == is_active)

        return len(list(self.session.execute(stmt).scalars().all()))

    def create(self, device: Device) -> Device:
        """Create a new device."""
        self.session.add(device)
        self.session.flush()
        return device

    def update_or_create(
        self,
        ip_address: str,
        hostname: str | None = None,
        vendor: str | None = None,
        device_type: str | None = None,
        platform: str | None = None,
        model: str | None = None,
        serial_number: str | None = None,
        software_version: str | None = None,
        sys_object_id: str | None = None,
        sys_description: str | None = None,
        metadata: dict | None = None,
        credential_profile_name: str | None = None,
    ) -> tuple[Device, bool]:
        """
        Update existing device or create new one.

        Returns:
            Tuple of (device, created) where created is True if new device
        """
        device = self.get_by_ip(ip_address)
        created = False

        if device is None:
            device = Device(ip_address=ip_address)
            created = True

        # Update fields if provided
        if hostname is not None:
            device.hostname = hostname
        if vendor is not None:
            device.vendor = vendor
        if device_type is not None:
            device.device_type = device_type
        if platform is not None:
            device.platform = platform
        if model is not None:
            device.model = model
        if serial_number is not None:
            device.serial_number = serial_number
        if software_version is not None:
            device.software_version = software_version
        if sys_object_id is not None:
            device.sys_object_id = sys_object_id
        if sys_description is not None:
            device.sys_description = sys_description
        if metadata is not None:
            device.metadata_ = metadata
        if credential_profile_name is not None:
            device.credential_profile_name = credential_profile_name

        device.last_seen = datetime.utcnow()
        device.is_active = True

        if created:
            self.session.add(device)

        self.session.flush()
        return device, created

    def delete(self, device: Device) -> None:
        """Delete a device."""
        self.session.delete(device)
        self.session.flush()

    def get_vendors(self) -> list[str]:
        """Get list of distinct vendors."""
        stmt = select(Device.vendor).distinct().where(Device.vendor.isnot(None))
        return [v for v in self.session.execute(stmt).scalars().all() if v]

    def get_device_types(self) -> list[str]:
        """Get list of distinct device types."""
        stmt = select(Device.device_type).distinct().where(Device.device_type.isnot(None))
        return [t for t in self.session.execute(stmt).scalars().all() if t]
