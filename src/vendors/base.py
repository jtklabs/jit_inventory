"""
Abstract base class for vendor-specific SNMP handling.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DeviceInfo:
    """Standardized device information across all vendors."""

    ip_address: str
    hostname: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    platform: str | None = None
    model: str | None = None
    serial_number: str | None = None
    software_version: str | None = None
    sys_object_id: str | None = None
    sys_description: str | None = None
    raw_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "platform": self.platform,
            "model": self.model,
            "serial_number": self.serial_number,
            "software_version": self.software_version,
            "sys_object_id": self.sys_object_id,
            "sys_description": self.sys_description,
            "raw_data": self.raw_data,
        }


class VendorHandler(ABC):
    """
    Abstract base class for vendor-specific SNMP handling.
    Each vendor module implements this to handle fingerprinting and data collection.
    """

    @property
    @abstractmethod
    def vendor_name(self) -> str:
        """Return vendor name (e.g., 'cisco', 'juniper')."""
        pass

    @property
    @abstractmethod
    def enterprise_id(self) -> int:
        """Return IANA enterprise number."""
        pass

    @abstractmethod
    def matches_sys_object_id(self, sys_object_id: str) -> bool:
        """
        Check if the sysObjectID belongs to this vendor.
        Returns True if this handler should process the device.
        """
        pass

    @abstractmethod
    def identify_device_type(
        self, sys_object_id: str, sys_descr: str | None
    ) -> dict[str, str | None]:
        """
        Identify device type, platform, and model from sysObjectID and sysDescr.
        Returns dict with 'device_type', 'platform', 'model' keys.
        """
        pass

    @abstractmethod
    def get_collection_oids(self) -> dict[str, str]:
        """
        Return dict of OIDs to collect for this vendor.
        Keys are field names, values are OIDs.
        """
        pass

    @abstractmethod
    def parse_collected_data(
        self, raw_data: dict[str, Any], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """
        Parse raw SNMP responses into structured data.
        Handle vendor-specific formatting and normalization.

        Args:
            raw_data: Dict of field names to SNMP values
            sys_descr: sysDescr string for fallback parsing (optional)
        """
        pass
