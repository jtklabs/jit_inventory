"""
Dell EMC Networking SNMP handling.

Dell EMC Networking (formerly Force10) devices use standard Entity MIB
for hardware inventory and Dell-specific MIBs for additional info.

sysObjectID format: 1.3.6.1.4.1.6027.* (Dell Networking/Force10)
                    1.3.6.1.4.1.674.* (Dell Inc - some models)

References:
- Dell Networking Enterprise OID: 6027 (Force10/Dell Networking)
- Dell Inc Enterprise OID: 674
- Uses standard Entity MIB (RFC 4133) for hardware info
- DELL-NETWORKING-CHASSIS-MIB for chassis-specific data
- sysDescr format varies:
  - "Dell EMC Networking OS10 Enterprise"
  - "Dell Networking OS9"
  - "Dell EMC Networking N3048EP-ON"
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
    entity_class: int | None = None
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
    stack_units: list[EntityComponent] = field(default_factory=list)
    all_components: list[EntityComponent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "chassis": self.chassis.to_dict() if self.chassis else None,
            "modules": [m.to_dict() for m in self.modules],
            "power_supplies": [p.to_dict() for p in self.power_supplies],
            "fans": [f.to_dict() for f in self.fans],
            "stack_units": [s.to_dict() for s in self.stack_units],
        }


class DellHandler(VendorHandler):
    """Handler for Dell EMC Networking devices."""

    # Dell Networking (Force10) enterprise ID
    ENTERPRISE_ID = 6027
    OID_PREFIX = "1.3.6.1.4.1.6027"

    # Dell Inc enterprise ID (some models use this)
    DELL_INC_ENTERPRISE_ID = 674
    DELL_INC_OID_PREFIX = "1.3.6.1.4.1.674"

    # Dell uses standard Entity MIB for most data
    DELL_OIDS = {
        # Entity MIB - chassis (index 1)
        "ent_serial": "1.3.6.1.2.1.47.1.1.1.1.11.1",
        "ent_model": "1.3.6.1.2.1.47.1.1.1.1.13.1",
        "ent_sw_rev": "1.3.6.1.2.1.47.1.1.1.1.10.1",
        "ent_descr": "1.3.6.1.2.1.47.1.1.1.1.2.1",
        "ent_hw_rev": "1.3.6.1.2.1.47.1.1.1.1.8.1",
        # Some Dell switches use different Entity indices
        "ent_serial_2": "1.3.6.1.2.1.47.1.1.1.1.11.2",
        "ent_model_2": "1.3.6.1.2.1.47.1.1.1.1.13.2",
        # Dell Networking chassis service tag (serial)
        # DELL-NETWORKING-CHASSIS-MIB::dellNetChassisServiceTag
        "dell_service_tag": "1.3.6.1.4.1.6027.3.26.1.3.4.1.13.1",
        # F10-CHASSIS-MIB::chSysSerialNumber (older Force10)
        "f10_serial": "1.3.6.1.4.1.6027.3.1.1.1.11.0",
    }

    # Entity MIB OID bases for walking
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

    @property
    def vendor_name(self) -> str:
        return "dell"

    @property
    def enterprise_id(self) -> int:
        return self.ENTERPRISE_ID

    def matches_sys_object_id(self, sys_object_id: str) -> bool:
        """Check if sysObjectID belongs to Dell."""
        normalized = sys_object_id.lstrip(".")
        # Match Dell Networking (Force10) or Dell Inc
        return (
            normalized.startswith("1.3.6.1.4.1.6027") or
            normalized.startswith("1.3.6.1.4.1.674")
        )

    def identify_device_type(
        self, sys_object_id: str, sys_descr: str | None
    ) -> dict[str, str | None]:
        """Identify Dell device type from sysDescr and sysObjectID."""
        result: dict[str, str | None] = {
            "device_type": "Switch",
            "platform": "Dell Networking",
            "model": None,
        }

        # Try to extract model and platform from sysDescr
        if sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            if model_info.get("model"):
                result["model"] = model_info["model"]
            if model_info.get("platform"):
                result["platform"] = model_info["platform"]
            if model_info.get("device_type"):
                result["device_type"] = model_info["device_type"]

        return result

    def _parse_model_from_sysdescr(self, sys_descr: str) -> dict[str, str | None]:
        """
        Extract model and platform from sysDescr.

        Dell sysDescr format examples:
        - "Dell EMC Networking OS10 Enterprise"
        - "Dell Networking N3048EP-ON, Dell Networking OS, Version 6.5.1.9"
        - "Dell EMC Networking S5248F-ON, Dell EMC SmartFabric OS10, Version 10.5.2.4"
        - "Dell Networking OS9 : Dell S6010-ON : Version 9.14(2.10)"
        - "Force10 Networks Real Time Operating System Software"
        """
        result: dict[str, str | None] = {
            "model": None,
            "platform": None,
            "device_type": None,
        }

        # Detect platform (OS10, OS9, FTOS)
        if "OS10" in sys_descr or "SmartFabric" in sys_descr:
            result["platform"] = "OS10"
        elif "OS9" in sys_descr:
            result["platform"] = "OS9"
        elif "Force10" in sys_descr or "FTOS" in sys_descr:
            result["platform"] = "FTOS"
        else:
            result["platform"] = "Dell Networking"

        # Extract model patterns
        model_patterns = [
            # S-series (data center)
            r"(S\d{4}[A-Z]*-ON)",
            r"(S\d{4}[A-Z]*)",
            # N-series (campus)
            r"(N\d{4}[A-Z]*-ON)",
            r"(N\d{4}[A-Z]*)",
            # Z-series (fabric)
            r"(Z\d{4}[A-Z]*-ON)",
            r"(Z\d{4}[A-Z]*)",
            # M-series (blade)
            r"(MX\d{4}[A-Z]*)",
            r"(M\d{4}[A-Z]*)",
            # C-series (aggregation)
            r"(C\d{4}[A-Z]*)",
            # E-series (legacy)
            r"(E\d{3,4}[A-Z]*)",
            # PowerSwitch
            r"PowerSwitch\s+(S\d+[A-Z\-]*)",
            r"PowerSwitch\s+(N\d+[A-Z\-]*)",
        ]

        for pattern in model_patterns:
            match = re.search(pattern, sys_descr, re.I)
            if match:
                result["model"] = match.group(1).upper()
                break

        # Determine device type from model
        if result["model"]:
            model_upper = result["model"].upper()
            if model_upper.startswith("S"):
                result["device_type"] = "Data Center Switch"
            elif model_upper.startswith("N"):
                result["device_type"] = "Campus Switch"
            elif model_upper.startswith("Z"):
                result["device_type"] = "Fabric Switch"
            elif model_upper.startswith("M"):
                result["device_type"] = "Blade Switch"
            elif model_upper.startswith("C"):
                result["device_type"] = "Aggregation Switch"
            elif model_upper.startswith("E"):
                result["device_type"] = "Edge Switch"
            else:
                result["device_type"] = "Switch"

        return result

    def get_collection_oids(self) -> dict[str, str]:
        """Return OIDs to collect for Dell devices."""
        return self.DELL_OIDS.copy()

    def parse_collected_data(
        self, raw_data: dict[str, Any], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """Parse Dell-specific SNMP responses."""
        parsed: dict[str, Any] = {}

        # Serial number - try multiple sources
        # Dell service tag from Dell-specific MIB
        dell_service_tag = raw_data.get("dell_service_tag", "")
        f10_serial = raw_data.get("f10_serial", "")
        ent_serial = raw_data.get("ent_serial", "")
        ent_serial_2 = raw_data.get("ent_serial_2", "")

        if dell_service_tag and dell_service_tag.strip():
            parsed["serial_number"] = dell_service_tag.strip()
        elif f10_serial and f10_serial.strip():
            parsed["serial_number"] = f10_serial.strip()
        elif ent_serial and ent_serial.strip():
            parsed["serial_number"] = ent_serial.strip()
        elif ent_serial_2 and ent_serial_2.strip():
            parsed["serial_number"] = ent_serial_2.strip()
        else:
            parsed["serial_number"] = None

        # Model name - try entity MIB
        ent_model = raw_data.get("ent_model", "")
        ent_model_2 = raw_data.get("ent_model_2", "")
        ent_descr = raw_data.get("ent_descr", "")

        if ent_model and ent_model.strip():
            parsed["model"] = ent_model.strip()
        elif ent_model_2 and ent_model_2.strip():
            parsed["model"] = ent_model_2.strip()
        elif ent_descr and ent_descr.strip():
            parsed["model"] = ent_descr.strip()
        elif sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            parsed["model"] = model_info.get("model")
        else:
            parsed["model"] = None

        # Software version - try entity MIB, then parse from sysDescr
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
        Extract software version from sysDescr.

        Examples:
        - "Dell Networking N3048EP-ON, Dell Networking OS, Version 6.5.1.9"
        - "Dell EMC Networking S5248F-ON, Dell EMC SmartFabric OS10, Version 10.5.2.4"
        - "Dell Networking OS9 : Dell S6010-ON : Version 9.14(2.10)"
        """
        if not sys_descr:
            return None

        version_patterns = [
            r"Version\s+(\d+\.\d+[\.\d]*(?:\([^\)]+\))?)",
            r"version\s+(\d+\.\d+[\.\d]*)",
            r"OS10[,\s]+(\d+\.\d+[\.\d]*)",
            r"OS9[,\s]+(\d+\.\d+[\.\d]*)",
            r"FTOS[,\s]+(\d+\.\d+[\.\d]*)",
        ]

        for pattern in version_patterns:
            match = re.search(pattern, sys_descr, re.I)
            if match:
                return match.group(1)

        return None

    def get_entity_mib_oids(self) -> dict[str, str]:
        """Return Entity MIB OID bases for walking."""
        return self.ENTITY_MIB_OIDS.copy()

    def parse_basic_info_from_entity_walk(
        self, walk_results: dict[str, list[tuple[str, str]]], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """
        Dell-specific override to handle parsing from sysDescr when Entity MIB
        doesn't have the required data.
        """
        # Call parent implementation first
        result = super().parse_basic_info_from_entity_walk(walk_results, sys_descr)

        # If no software version from Entity MIB, parse from sysDescr
        if not result.get("software_version") and sys_descr:
            result["software_version"] = self._extract_version_from_sysdescr(sys_descr)

        # If no model from Entity MIB, parse from sysDescr
        if not result.get("model") and sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            result["model"] = model_info.get("model")

        return result

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
        components: dict[int, EntityComponent] = {}

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
            elif comp.entity_class == 11:  # Stack
                if comp.serial_number or comp.model_name:
                    inventory.stack_units.append(comp)
            elif comp.entity_class == 9:  # Module
                if comp.serial_number or comp.model_name:
                    inventory.modules.append(comp)
            elif comp.entity_class == 6:  # Power supply
                inventory.power_supplies.append(comp)
            elif comp.entity_class == 7:  # Fan
                inventory.fans.append(comp)

        # Sort by position
        inventory.modules.sort(key=lambda x: (x.contained_in or 0, x.parent_rel_pos or 0))
        inventory.stack_units.sort(key=lambda x: x.parent_rel_pos or 0)

        return inventory
