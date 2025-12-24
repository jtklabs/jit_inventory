"""
Fortinet FortiGate SNMP handling.

FortiGate firewalls use FORTINET-FORTIGATE-MIB for device information.
sysObjectID format: 1.3.6.1.4.1.12356.101.1.* (product model OIDs)

References:
- Fortinet Enterprise OID: 12356
- FORTINET-FORTIGATE-MIB: Contains system info (serial, version)
- sysDescr format varies by FortiOS version
"""
import re
from dataclasses import dataclass, field
from typing import Any

from src.vendors.base import VendorHandler


@dataclass
class EntityComponent:
    """Represents a physical component."""

    index: int
    description: str | None = None
    name: str | None = None
    serial_number: str | None = None
    model_name: str | None = None
    entity_class: int | None = None

    @property
    def class_name(self) -> str:
        """Return human-readable class name."""
        class_map = {
            1: "other",
            2: "unknown",
            3: "chassis",
            6: "power_supply",
            7: "fan",
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
        }


@dataclass
class DeviceInventory:
    """Complete device inventory for FortiGate firewalls."""

    chassis: EntityComponent | None = None
    power_supplies: list[EntityComponent] = field(default_factory=list)
    fans: list[EntityComponent] = field(default_factory=list)
    all_components: list[EntityComponent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "chassis": self.chassis.to_dict() if self.chassis else None,
            "power_supplies": [p.to_dict() for p in self.power_supplies],
            "fans": [f.to_dict() for f in self.fans],
        }


class FortinetHandler(VendorHandler):
    """Handler for Fortinet FortiGate firewall devices."""

    ENTERPRISE_ID = 12356
    OID_PREFIX = "1.3.6.1.4.1.12356"

    # FORTINET-FORTIGATE-MIB OIDs for device information
    # Base: 1.3.6.1.4.1.12356.101.4.1
    FORTINET_OIDS = {
        # fgSysVersion - Firmware version
        "sw_version": "1.3.6.1.4.1.12356.101.4.1.1.0",
        # fgSysSerial - Serial number (found in system info)
        "serial_number": "1.3.6.1.4.1.12356.100.1.1.1.0",
        # Alternative serial location
        "serial_alt": "1.3.6.1.4.1.12356.1.3.0",
        # Entity MIB fallbacks
        "ent_serial": "1.3.6.1.2.1.47.1.1.1.1.11.1",
        "ent_model": "1.3.6.1.2.1.47.1.1.1.1.13.1",
        "ent_descr": "1.3.6.1.2.1.47.1.1.1.1.2.1",
    }

    # Entity MIB OID bases for walking
    ENTITY_MIB_OIDS = {
        "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2",
        "entPhysicalClass": "1.3.6.1.2.1.47.1.1.1.1.5",
        "entPhysicalName": "1.3.6.1.2.1.47.1.1.1.1.7",
        "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11",
        "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13",
    }

    # Known FortiGate model patterns from sysObjectID
    # Format: 1.3.6.1.4.1.12356.101.1.MODEL_ID
    MODEL_OID_MAP = {
        # FortiGate physical appliances
        "30": "FortiGate-30",
        "40": "FortiGate-40",
        "50": "FortiGate-50",
        "60": "FortiGate-60",
        "80": "FortiGate-80",
        "100": "FortiGate-100",
        "200": "FortiGate-200",
        "300": "FortiGate-300",
        "400": "FortiGate-400",
        "500": "FortiGate-500",
        "600": "FortiGate-600",
        "800": "FortiGate-800",
        "1000": "FortiGate-1000",
        "1240": "FortiGate-1240B",
        "1500": "FortiGate-1500",
        "2000": "FortiGate-2000",
        "3000": "FortiGate-3000",
        "3100": "FortiGate-3100D",
        "3200": "FortiGate-3200D",
        "3600": "FortiGate-3600",
        "3700": "FortiGate-3700D",
        "3800": "FortiGate-3800D",
        "3960": "FortiGate-3960E",
        "3980": "FortiGate-3980E",
        "5001": "FortiGate-5001",
        "5060": "FortiGate-5060",
        "5144": "FortiGate-5144C",
        # FortiGate E-series
        "40f": "FortiGate-40F",
        "60e": "FortiGate-60E",
        "60f": "FortiGate-60F",
        "80e": "FortiGate-80E",
        "80f": "FortiGate-80F",
        "100e": "FortiGate-100E",
        "100f": "FortiGate-100F",
        "200e": "FortiGate-200E",
        "200f": "FortiGate-200F",
        "400e": "FortiGate-400E",
        "400f": "FortiGate-400F",
        "600e": "FortiGate-600E",
        "600f": "FortiGate-600F",
        "1100e": "FortiGate-1100E",
        "1800f": "FortiGate-1800F",
        "2200e": "FortiGate-2200E",
        "2600f": "FortiGate-2600F",
        # FortiGate VM
        "fgtvm": "FortiGate-VM",
        "fgtvm64": "FortiGate-VM64",
    }

    @property
    def vendor_name(self) -> str:
        return "fortinet"

    @property
    def enterprise_id(self) -> int:
        return self.ENTERPRISE_ID

    def matches_sys_object_id(self, sys_object_id: str) -> bool:
        """Check if sysObjectID belongs to Fortinet."""
        normalized = sys_object_id.lstrip(".")
        return normalized.startswith("1.3.6.1.4.1.12356")

    def identify_device_type(
        self, sys_object_id: str, sys_descr: str | None
    ) -> dict[str, str | None]:
        """Identify Fortinet device type from sysDescr and sysObjectID."""
        result: dict[str, str | None] = {
            "device_type": "Firewall",
            "platform": "FortiOS",
            "model": None,
        }

        # Try to extract model from sysDescr first
        if sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            if model_info.get("model"):
                result["model"] = model_info["model"]
            if model_info.get("device_type"):
                result["device_type"] = model_info["device_type"]

        # If no model from sysDescr, try sysObjectID
        if not result["model"]:
            model_from_oid = self._parse_model_from_oid(sys_object_id)
            if model_from_oid:
                result["model"] = model_from_oid

        return result

    def _parse_model_from_sysdescr(self, sys_descr: str) -> dict[str, str | None]:
        """
        Extract model and device type from sysDescr.

        FortiGate sysDescr format examples:
        - "FortiGate-60E v6.4.5,build1828,210217"
        - "FortiGate-100F"
        - "FortiWiFi-60E"
        """
        result: dict[str, str | None] = {
            "model": None,
            "device_type": None,
        }

        # Extract model patterns
        model_patterns = [
            r"(FortiGate-\d+[A-Z]*)",
            r"(FortiWiFi-\d+[A-Z]*)",
            r"(FortiGate-VM\d*)",
            r"(FGT-\d+[A-Z]*)",
            r"(FWF-\d+[A-Z]*)",
        ]

        for pattern in model_patterns:
            match = re.search(pattern, sys_descr, re.I)
            if match:
                result["model"] = match.group(1)
                break

        # Determine device type
        sys_descr_lower = sys_descr.lower()
        if "fortiwifi" in sys_descr_lower or "fwf-" in sys_descr_lower:
            result["device_type"] = "Wireless Firewall"
        elif "fortigate-vm" in sys_descr_lower or "fgt-vm" in sys_descr_lower:
            result["device_type"] = "Virtual Firewall"
        else:
            result["device_type"] = "Firewall"

        return result

    def _parse_model_from_oid(self, sys_object_id: str) -> str | None:
        """
        Try to extract model from sysObjectID.

        FortiGate sysObjectID format: 1.3.6.1.4.1.12356.101.1.MODEL_ID
        """
        match = re.search(r"12356\.101\.1\.(\d+)", sys_object_id)
        if match:
            model_id = match.group(1)
            return self.MODEL_OID_MAP.get(model_id, f"FortiGate-{model_id}")

        return None

    def get_collection_oids(self) -> dict[str, str]:
        """Return OIDs to collect for FortiGate devices."""
        return self.FORTINET_OIDS.copy()

    def parse_collected_data(
        self, raw_data: dict[str, Any], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """Parse FortiGate-specific SNMP responses."""
        parsed: dict[str, Any] = {}

        # Serial number: try multiple sources
        serial = raw_data.get("serial_number", "")
        serial_alt = raw_data.get("serial_alt", "")
        ent_serial = raw_data.get("ent_serial", "")

        if serial and serial.strip():
            parsed["serial_number"] = serial.strip()
        elif serial_alt and serial_alt.strip():
            # Older format might have "FortiGate-60 3.00,build0730,..."
            # Try to extract serial from this
            parsed["serial_number"] = self._extract_serial_from_alt(serial_alt.strip())
        elif ent_serial and ent_serial.strip():
            parsed["serial_number"] = ent_serial.strip()
        else:
            parsed["serial_number"] = None

        # Model: prefer Entity MIB or sysDescr
        ent_model = raw_data.get("ent_model", "")
        ent_descr = raw_data.get("ent_descr", "")

        if ent_model and ent_model.strip():
            parsed["model"] = ent_model.strip()
        elif ent_descr and ent_descr.strip():
            model_match = re.search(r"(FortiGate-\d+[A-Z]*)", ent_descr, re.I)
            if model_match:
                parsed["model"] = model_match.group(1)
            else:
                parsed["model"] = ent_descr.strip()
        elif sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            parsed["model"] = model_info.get("model")
        else:
            parsed["model"] = None

        # Software version
        sw_version = raw_data.get("sw_version", "")
        if sw_version and sw_version.strip():
            parsed["software_version"] = sw_version.strip()
        elif sys_descr:
            parsed["software_version"] = self._extract_version_from_sysdescr(sys_descr)
        else:
            parsed["software_version"] = None

        return parsed

    def _extract_serial_from_alt(self, alt_data: str) -> str | None:
        """Extract serial from alternative format string."""
        # Format might be "FortiGate-60 3.00,build0730,080919"
        # In this case, we might not have a serial
        return None

    def _extract_version_from_sysdescr(self, sys_descr: str) -> str | None:
        """
        Extract FortiOS version from sysDescr.

        Example: "FortiGate-60E v6.4.5,build1828,210217"
        """
        if not sys_descr:
            return None

        version_patterns = [
            r"v(\d+\.\d+\.\d+)",
            r"FortiOS\s+v?(\d+\.\d+\.\d+)",
            r",build(\d+),",
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
        """Parse Entity MIB walk results into structured inventory."""
        components: dict[int, EntityComponent] = {}

        def get_index(oid: str, base_oid: str) -> int | None:
            suffix = oid.replace(base_oid + ".", "")
            try:
                return int(suffix.split(".")[0])
            except (ValueError, IndexError):
                return None

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
                elif oid_name == "entPhysicalClass":
                    try:
                        comp.entity_class = int(value_str) if value_str else None
                    except ValueError:
                        pass
                elif oid_name == "entPhysicalName":
                    comp.name = value_str
                elif oid_name == "entPhysicalSerialNum":
                    comp.serial_number = value_str
                elif oid_name == "entPhysicalModelName":
                    comp.model_name = value_str

        inventory = DeviceInventory()
        inventory.all_components = list(components.values())

        for comp in components.values():
            if not comp.description and not comp.name and not comp.model_name:
                continue

            if comp.entity_class == 3:
                if inventory.chassis is None:
                    inventory.chassis = comp
            elif comp.entity_class == 6:
                inventory.power_supplies.append(comp)
            elif comp.entity_class == 7:
                inventory.fans.append(comp)

        return inventory
