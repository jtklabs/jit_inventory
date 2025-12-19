"""
SQLAlchemy ORM models for the inventory database.
"""
from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class Device(Base):
    """Discovered network device."""

    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    ip_address: Mapped[str] = mapped_column(INET, unique=True, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    vendor: Mapped[str | None] = mapped_column(String(100))
    device_type: Mapped[str | None] = mapped_column(String(100))
    platform: Mapped[str | None] = mapped_column(String(100))
    model: Mapped[str | None] = mapped_column(String(100))
    serial_number: Mapped[str | None] = mapped_column(String(100))
    software_version: Mapped[str | None] = mapped_column(String(100))
    sys_object_id: Mapped[str | None] = mapped_column(String(255))
    sys_description: Mapped[str | None] = mapped_column(Text)
    first_discovered: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    last_updated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    metadata_: Mapped[dict[str, Any] | None] = mapped_column("metadata", JSONB)
    # Associated credential profile that works for this device
    credential_profile_name: Mapped[str | None] = mapped_column(String(255))

    scan_history: Mapped[list["ScanHistory"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Device {self.ip_address} ({self.hostname})>"


class ScanHistory(Base):
    """Historical record of device scans."""

    __tablename__ = "scan_history"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    device_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=False), ForeignKey("devices.id", ondelete="SET NULL")
    )
    ip_address: Mapped[str] = mapped_column(INET, nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    scan_status: Mapped[str] = mapped_column(String(50), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error_message: Mapped[str | None] = mapped_column(Text)

    # Snapshot of collected data
    hostname: Mapped[str | None] = mapped_column(String(255))
    vendor: Mapped[str | None] = mapped_column(String(100))
    device_type: Mapped[str | None] = mapped_column(String(100))
    platform: Mapped[str | None] = mapped_column(String(100))
    model: Mapped[str | None] = mapped_column(String(100))
    serial_number: Mapped[str | None] = mapped_column(String(100))
    software_version: Mapped[str | None] = mapped_column(String(100))
    sys_object_id: Mapped[str | None] = mapped_column(String(255))
    sys_description: Mapped[str | None] = mapped_column(Text)
    raw_snmp_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    credential_profile_name: Mapped[str | None] = mapped_column(String(255))
    snmp_version: Mapped[str | None] = mapped_column(String(10))

    device: Mapped[Device | None] = relationship(back_populates="scan_history")

    def __repr__(self) -> str:
        return f"<ScanHistory {self.ip_address} @ {self.started_at}>"


class BatchJob(Base):
    """Batch scanning job."""

    __tablename__ = "batch_jobs"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    total_targets: Mapped[int] = mapped_column(Integer, nullable=False)
    completed_count: Mapped[int] = mapped_column(Integer, default=0)
    success_count: Mapped[int] = mapped_column(Integer, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    input_type: Mapped[str | None] = mapped_column(String(50))
    input_data: Mapped[str | None] = mapped_column(Text)
    credential_profile_name: Mapped[str | None] = mapped_column(String(255))

    targets: Mapped[list["BatchJobTarget"]] = relationship(
        back_populates="batch_job", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<BatchJob {self.id} ({self.status})>"


class BatchJobTarget(Base):
    """Individual target within a batch job."""

    __tablename__ = "batch_job_targets"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    batch_job_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("batch_jobs.id", ondelete="CASCADE"), nullable=False
    )
    ip_address: Mapped[str] = mapped_column(INET, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    scan_history_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=False), ForeignKey("scan_history.id")
    )
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)

    batch_job: Mapped[BatchJob] = relationship(back_populates="targets")

    def __repr__(self) -> str:
        return f"<BatchJobTarget {self.ip_address} ({self.status})>"


class CredentialProfile(Base):
    """SNMP credential profile metadata (secrets stored externally)."""

    __tablename__ = "credential_profiles"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    snmp_version: Mapped[str] = mapped_column(String(10), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    # Priority for auto-discovery (lower = tried first)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    v3_username: Mapped[str | None] = mapped_column(String(100))
    v3_auth_protocol: Mapped[str | None] = mapped_column(String(20))
    v3_priv_protocol: Mapped[str | None] = mapped_column(String(20))
    v3_security_level: Mapped[str | None] = mapped_column(String(20))

    def __repr__(self) -> str:
        return f"<CredentialProfile {self.name} ({self.snmp_version})>"
