"""
Abstract base class for vendor-specific SNMP handling.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


# Standard Entity MIB OIDs (RFC 4133) - used by most vendors
ENTITY_MIB_OIDS = {
    "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2",
    "entPhysicalClass": "1.3.6.1.2.1.47.1.1.1.1.5",
    "entPhysicalName": "1.3.6.1.2.1.47.1.1.1.1.7",
    "entPhysicalSoftwareRev": "1.3.6.1.2.1.47.1.1.1.1.10",
    "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11",
    "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13",
}

# Entity physical class values
ENTITY_CLASS_CHASSIS = 3
ENTITY_CLASS_MODULE = 9
ENTITY_CLASS_STACK = 11


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

    def parse_basic_info_from_entity_walk(
        self, walk_results: dict[str, list[tuple[str, str]]], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """
        Extract basic device info (serial, model, version) from Entity MIB walk results.

        This method uses entity class to find the chassis component rather than
        hardcoded indices, making it work across different device models.

        Args:
            walk_results: Dict mapping OID name to list of (full_oid, value) tuples
                          Expected keys: entPhysicalClass, entPhysicalSerialNum,
                                        entPhysicalModelName, entPhysicalSoftwareRev

        Returns:
            Dict with serial_number, model, software_version (any may be None)
        """
        result: dict[str, Any] = {
            "serial_number": None,
            "model": None,
            "software_version": None,
        }

        # Build a map of index -> data from walk results
        entities: dict[int, dict[str, Any]] = {}

        def get_index(oid: str, base_oid: str) -> int | None:
            """Extract entity index from full OID."""
            suffix = oid.replace(base_oid + ".", "")
            try:
                return int(suffix.split(".")[0])
            except (ValueError, IndexError):
                return None

        # Parse entity classes first to identify chassis/stack members
        class_results = walk_results.get("entPhysicalClass", [])
        for full_oid, value in class_results:
            idx = get_index(full_oid, ENTITY_MIB_OIDS["entPhysicalClass"])
            if idx is not None:
                try:
                    entities[idx] = {"class": int(value)}
                except ValueError:
                    pass

        # Parse serial numbers
        serial_results = walk_results.get("entPhysicalSerialNum", [])
        for full_oid, value in serial_results:
            idx = get_index(full_oid, ENTITY_MIB_OIDS["entPhysicalSerialNum"])
            if idx is not None and value and value.strip():
                if idx not in entities:
                    entities[idx] = {}
                entities[idx]["serial"] = value.strip()

        # Parse model names
        model_results = walk_results.get("entPhysicalModelName", [])
        for full_oid, value in model_results:
            idx = get_index(full_oid, ENTITY_MIB_OIDS["entPhysicalModelName"])
            if idx is not None and value and value.strip():
                if idx not in entities:
                    entities[idx] = {}
                entities[idx]["model"] = value.strip()

        # Parse software revisions
        sw_results = walk_results.get("entPhysicalSoftwareRev", [])
        for full_oid, value in sw_results:
            idx = get_index(full_oid, ENTITY_MIB_OIDS["entPhysicalSoftwareRev"])
            if idx is not None and value and value.strip():
                if idx not in entities:
                    entities[idx] = {}
                entities[idx]["software_rev"] = value.strip()

        # Find chassis or stack components (class 3 or 11) with serial numbers
        chassis_candidates = []
        for idx, data in entities.items():
            entity_class = data.get("class", 0)
            if entity_class in (ENTITY_CLASS_CHASSIS, ENTITY_CLASS_STACK):
                if data.get("serial"):
                    chassis_candidates.append((idx, data))

        # Sort by index (lower typically = main chassis or stack master)
        chassis_candidates.sort(key=lambda x: x[0])

        if chassis_candidates:
            # Use first chassis/stack with a serial number
            _, chassis_data = chassis_candidates[0]
            result["serial_number"] = chassis_data.get("serial")
            result["model"] = chassis_data.get("model")
            result["software_version"] = chassis_data.get("software_rev")
        else:
            # Fallback: find any entity with serial number (preferring lower index)
            serial_candidates = [
                (idx, data) for idx, data in entities.items() if data.get("serial")
            ]
            serial_candidates.sort(key=lambda x: x[0])

            if serial_candidates:
                _, fallback_data = serial_candidates[0]
                result["serial_number"] = fallback_data.get("serial")
                result["model"] = fallback_data.get("model")
                result["software_version"] = fallback_data.get("software_rev")

        return result

    def get_entity_walk_oids(self) -> dict[str, str]:
        """
        Return Entity MIB OIDs to walk for basic device info.

        Override in subclass if vendor needs different OIDs.
        """
        return {
            "entPhysicalClass": ENTITY_MIB_OIDS["entPhysicalClass"],
            "entPhysicalSerialNum": ENTITY_MIB_OIDS["entPhysicalSerialNum"],
            "entPhysicalModelName": ENTITY_MIB_OIDS["entPhysicalModelName"],
            "entPhysicalSoftwareRev": ENTITY_MIB_OIDS["entPhysicalSoftwareRev"],
        }
