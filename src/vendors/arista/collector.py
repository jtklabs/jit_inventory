"""
Arista EOS-specific SNMP handling.

Arista devices use standard Entity MIB for hardware inventory.
sysObjectID format: 1.3.6.1.4.1.30065.1.3011.* (varies by model)

References:
- Arista Enterprise OID: 30065
- Uses standard Entity MIB (RFC 4133) for hardware info
- sysDescr format: "Arista Networks EOS version X.X.X running on an Arista Networks MODEL"
"""
import re
from dataclasses import dataclass, field
from typing import Any

from src.vendors.base import VendorHandler


@dataclass
class EntityComponent:
    """Represents a physical component from Entity MIB."""

    index: int
    description: str | None = None
    vendor_type: str | None = None
    contained_in: int | None = None
    entity_class: int | None = None  # 3=chassis, 5=container, 9=module, 10=port
    parent_rel_pos: int | None = None
    name: str | None = None
    hardware_rev: str | None = None
    firmware_rev: str | None = None
    software_rev: str | None = None
    serial_number: str | None = None
    mfg_name: str | None = None
    model_name: str | None = None
    is_fru: bool | None = None

    @property
    def class_name(self) -> str:
        """Return human-readable class name."""
        class_map = {
            1: "other",
            2: "unknown",
            3: "chassis",
            4: "backplane",
            5: "container",
            6: "power_supply",
            7: "fan",
            8: "sensor",
            9: "module",
            10: "port",
            11: "stack",
            12: "cpu",
        }
        return class_map.get(self.entity_class or 0, "unknown")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "index": self.index,
            "class": self.class_name,
            "name": self.name,
            "description": self.description,
            "model": self.model_name,
            "serial": self.serial_number,
            "hardware_rev": self.hardware_rev,
            "firmware_rev": self.firmware_rev,
            "software_rev": self.software_rev,
            "manufacturer": self.mfg_name,
            "is_fru": self.is_fru,
        }


@dataclass
class DeviceInventory:
    """Complete device inventory with modules and components."""

    chassis: EntityComponent | None = None
    modules: list[EntityComponent] = field(default_factory=list)
    power_supplies: list[EntityComponent] = field(default_factory=list)
    fans: list[EntityComponent] = field(default_factory=list)
    transceivers: list[EntityComponent] = field(default_factory=list)
    all_components: list[EntityComponent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "chassis": self.chassis.to_dict() if self.chassis else None,
            "modules": [m.to_dict() for m in self.modules],
            "power_supplies": [p.to_dict() for p in self.power_supplies],
            "fans": [f.to_dict() for f in self.fans],
            "transceivers": [t.to_dict() for t in self.transceivers],
        }


class AristaHandler(VendorHandler):
    """Handler for Arista EOS network devices."""

    ENTERPRISE_ID = 30065
    OID_PREFIX = "1.3.6.1.4.1.30065"

    # Arista uses standard Entity MIB - no vendor-specific OIDs needed for basic info
    # Data is collected via Entity MIB walking
    ARISTA_OIDS = {
        # Entity MIB index 1 (chassis)
        "ent_serial": "1.3.6.1.2.1.47.1.1.1.1.11.1",
        "ent_model": "1.3.6.1.2.1.47.1.1.1.1.13.1",
        "ent_sw_rev": "1.3.6.1.2.1.47.1.1.1.1.10.1",
        "ent_descr": "1.3.6.1.2.1.47.1.1.1.1.2.1",
        "ent_hw_rev": "1.3.6.1.2.1.47.1.1.1.1.8.1",
        # Some Arista devices use index 100000001 for chassis
        "ent_serial_alt": "1.3.6.1.2.1.47.1.1.1.1.11.100000001",
        "ent_model_alt": "1.3.6.1.2.1.47.1.1.1.1.13.100000001",
    }

    # Entity MIB OID bases for walking (same as Cisco - standard MIB)
    ENTITY_MIB_OIDS = {
        "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2",
        "entPhysicalVendorType": "1.3.6.1.2.1.47.1.1.1.1.3",
        "entPhysicalContainedIn": "1.3.6.1.2.1.47.1.1.1.1.4",
        "entPhysicalClass": "1.3.6.1.2.1.47.1.1.1.1.5",
        "entPhysicalParentRelPos": "1.3.6.1.2.1.47.1.1.1.1.6",
        "entPhysicalName": "1.3.6.1.2.1.47.1.1.1.1.7",
        "entPhysicalHardwareRev": "1.3.6.1.2.1.47.1.1.1.1.8",
        "entPhysicalFirmwareRev": "1.3.6.1.2.1.47.1.1.1.1.9",
        "entPhysicalSoftwareRev": "1.3.6.1.2.1.47.1.1.1.1.10",
        "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11",
        "entPhysicalMfgName": "1.3.6.1.2.1.47.1.1.1.1.12",
        "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13",
        "entPhysicalIsFRU": "1.3.6.1.2.1.47.1.1.1.1.16",
    }

    # Known Arista model patterns from sysObjectID
    # Format: 1.3.6.1.4.1.30065.1.3011.MODEL_ID
    MODEL_OID_MAP = {
        # 7000 series (modular)
        "7280": "7280",
        "7500": "7500",
        "7504": "7504",
        "7508": "7508",
        # 7000 fixed series
        "7050": "7050",
        "7060": "7060",
        "7010": "7010",
        "7020": "7020",
        "7150": "7150",
        "7160": "7160",
        "7170": "7170",
        # 7300 series
        "7300": "7300",
        "7320": "7320",
        "7368": "7368",
        # 7800 series
        "7800": "7800",
        # 720 series
        "720": "720",
        "722": "722",
        # CCS series (CloudVision)
        "CCS": "CloudVision",
    }

    @property
    def vendor_name(self) -> str:
        return "arista"

    @property
    def enterprise_id(self) -> int:
        return self.ENTERPRISE_ID

    def matches_sys_object_id(self, sys_object_id: str) -> bool:
        """Check if sysObjectID belongs to Arista."""
        normalized = sys_object_id.lstrip(".")
        return normalized.startswith("1.3.6.1.4.1.30065")

    def identify_device_type(
        self, sys_object_id: str, sys_descr: str | None
    ) -> dict[str, str | None]:
        """Identify Arista device type from sysDescr and sysObjectID."""
        result: dict[str, str | None] = {
            "device_type": "switch",  # Arista primarily makes switches
            "platform": "EOS",
            "model": None,
        }

        # Try to extract model from sysDescr first (most reliable)
        if sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            if model_info.get("model"):
                result["model"] = model_info["model"]
            if model_info.get("device_type"):
                result["device_type"] = model_info["device_type"]

        # If no model from sysDescr, try sysObjectID
        if not result["model"]:
            result["model"] = self._parse_model_from_oid(sys_object_id)

        return result

    def _parse_model_from_sysdescr(self, sys_descr: str) -> dict[str, str | None]:
        """
        Extract model and device type from sysDescr.

        Arista sysDescr format examples:
        - "Arista Networks EOS version 4.28.3M running on an Arista Networks DCS-7050TX-64"
        - "Arista Networks EOS version 4.27.0F running on an Arista Networks DCS-7280SR-48C6"
        - "Arista Networks EOS version 4.25.4M running on an Arista Networks CCS-720XP-48ZC2"
        """
        result: dict[str, str | None] = {
            "model": None,
            "device_type": None,
        }

        # Extract model from "running on an Arista Networks MODEL"
        model_patterns = [
            # DCS (Data Center Switch) series
            r"running on an Arista Networks (DCS-\d+[A-Z0-9\-]+)",
            # CCS (CloudVision) series
            r"running on an Arista Networks (CCS-\d+[A-Z0-9\-]+)",
            # Generic pattern
            r"running on an Arista Networks ([A-Z0-9\-]+)",
            # Alternative format without "running on"
            r"Arista Networks ([A-Z]+-\d+[A-Z0-9\-]+)",
        ]

        for pattern in model_patterns:
            match = re.search(pattern, sys_descr, re.I)
            if match:
                result["model"] = match.group(1).upper()
                break

        # Determine device type from model
        if result["model"]:
            model_lower = result["model"].lower()
            if "ccs" in model_lower or "cvp" in model_lower:
                result["device_type"] = "Management"
            elif any(x in model_lower for x in ["7500", "7504", "7508", "7800"]):
                result["device_type"] = "Modular Switch"
            else:
                result["device_type"] = "Switch"

        return result

    def _parse_model_from_oid(self, sys_object_id: str) -> str | None:
        """
        Try to extract model from sysObjectID.

        Arista sysObjectID format: 1.3.6.1.4.1.30065.1.3011.MODEL_SUFFIX
        """
        # Extract the suffix after 30065
        match = re.search(r"30065\.1\.(\d+)\.?", sys_object_id)
        if match:
            model_id = match.group(1)
            # Try to map known model IDs
            for key, model in self.MODEL_OID_MAP.items():
                if key in model_id:
                    return f"DCS-{model}"

        return None

    def get_collection_oids(self) -> dict[str, str]:
        """Return OIDs to collect for Arista devices."""
        return self.ARISTA_OIDS.copy()

    def parse_collected_data(
        self, raw_data: dict[str, Any], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """Parse Arista-specific SNMP responses."""
        parsed: dict[str, Any] = {}

        # Serial number: try primary index, then alternate
        ent_serial = raw_data.get("ent_serial", "")
        ent_serial_alt = raw_data.get("ent_serial_alt", "")

        if ent_serial and ent_serial.strip():
            parsed["serial_number"] = ent_serial.strip()
        elif ent_serial_alt and ent_serial_alt.strip():
            parsed["serial_number"] = ent_serial_alt.strip()
        else:
            parsed["serial_number"] = None

        # Model name: try primary index, then alternate, then sysDescr
        ent_model = raw_data.get("ent_model", "")
        ent_model_alt = raw_data.get("ent_model_alt", "")
        ent_descr = raw_data.get("ent_descr", "")

        if ent_model and ent_model.strip():
            parsed["model"] = ent_model.strip()
        elif ent_model_alt and ent_model_alt.strip():
            parsed["model"] = ent_model_alt.strip()
        elif ent_descr and ent_descr.strip():
            parsed["model"] = ent_descr.strip()
        elif sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            parsed["model"] = model_info.get("model")
        else:
            parsed["model"] = None

        # Software version: try entity MIB, then parse from sysDescr
        ent_sw_rev = raw_data.get("ent_sw_rev", "")

        if ent_sw_rev and ent_sw_rev.strip():
            parsed["software_version"] = ent_sw_rev.strip()
        elif sys_descr:
            parsed["software_version"] = self._extract_version_from_sysdescr(sys_descr)
        else:
            parsed["software_version"] = None

        return parsed

    def _extract_version_from_sysdescr(self, sys_descr: str) -> str | None:
        """
        Extract EOS version from sysDescr.

        Example: "Arista Networks EOS version 4.28.3M running on..."
        """
        if not sys_descr:
            return None

        # EOS version pattern: X.X.XY (e.g., 4.28.3M, 4.27.0F)
        version_patterns = [
            r"EOS version (\d+\.\d+\.\d+[A-Z]*)",
            r"EOS (\d+\.\d+\.\d+[A-Z]*)",
            r"version (\d+\.\d+\.\d+[A-Z]*)",
        ]

        for pattern in version_patterns:
            match = re.search(pattern, sys_descr, re.I)
            if match:
                return match.group(1)

        return None

    def get_entity_mib_oids(self) -> dict[str, str]:
        """Return Entity MIB OID bases for walking."""
        return self.ENTITY_MIB_OIDS.copy()

    def parse_entity_table(
        self, walk_results: dict[str, list[tuple[str, str]]]
    ) -> DeviceInventory:
        """
        Parse Entity MIB walk results into structured inventory.

        Args:
            walk_results: Dict mapping OID name to list of (full_oid, value) tuples

        Returns:
            DeviceInventory with categorized components
        """
        # Build component dict by index
        components: dict[int, EntityComponent] = {}

        # Helper to extract index from OID
        def get_index(oid: str, base_oid: str) -> int | None:
            suffix = oid.replace(base_oid + ".", "")
            try:
                return int(suffix.split(".")[0])
            except (ValueError, IndexError):
                return None

        # Parse each OID type
        for oid_name, results in walk_results.items():
            base_oid = self.ENTITY_MIB_OIDS.get(oid_name)
            if not base_oid:
                continue

            for full_oid, value in results:
                idx = get_index(full_oid, base_oid)
                if idx is None:
                    continue

                if idx not in components:
                    components[idx] = EntityComponent(index=idx)

                comp = components[idx]
                value_str = str(value).strip() if value else None

                if oid_name == "entPhysicalDescr":
                    comp.description = value_str
                elif oid_name == "entPhysicalVendorType":
                    comp.vendor_type = value_str
                elif oid_name == "entPhysicalContainedIn":
                    try:
                        comp.contained_in = int(value_str) if value_str else None
                    except ValueError:
                        pass
                elif oid_name == "entPhysicalClass":
                    try:
                        comp.entity_class = int(value_str) if value_str else None
                    except ValueError:
                        pass
                elif oid_name == "entPhysicalParentRelPos":
                    try:
                        comp.parent_rel_pos = int(value_str) if value_str else None
                    except ValueError:
                        pass
                elif oid_name == "entPhysicalName":
                    comp.name = value_str
                elif oid_name == "entPhysicalHardwareRev":
                    comp.hardware_rev = value_str
                elif oid_name == "entPhysicalFirmwareRev":
                    comp.firmware_rev = value_str
                elif oid_name == "entPhysicalSoftwareRev":
                    comp.software_rev = value_str
                elif oid_name == "entPhysicalSerialNum":
                    comp.serial_number = value_str
                elif oid_name == "entPhysicalMfgName":
                    comp.mfg_name = value_str
                elif oid_name == "entPhysicalModelName":
                    comp.model_name = value_str
                elif oid_name == "entPhysicalIsFRU":
                    comp.is_fru = value_str in ("1", "true", "True")

        # Build inventory from components
        inventory = DeviceInventory()
        inventory.all_components = list(components.values())

        for comp in components.values():
            # Skip empty/placeholder entries
            if not comp.description and not comp.name and not comp.model_name:
                continue

            if comp.entity_class == 3:  # Chassis
                if inventory.chassis is None:
                    inventory.chassis = comp
            elif comp.entity_class == 9:  # Module
                if comp.serial_number or comp.model_name:
                    inventory.modules.append(comp)
            elif comp.entity_class == 6:  # Power supply
                inventory.power_supplies.append(comp)
            elif comp.entity_class == 7:  # Fan
                inventory.fans.append(comp)
            elif comp.entity_class == 10:  # Port (transceivers)
                # Arista reports transceivers as ports with serial numbers
                if comp.serial_number and comp.model_name:
                    inventory.transceivers.append(comp)

        # Sort modules by position
        inventory.modules.sort(key=lambda x: (x.contained_in or 0, x.parent_rel_pos or 0))

        return inventory
