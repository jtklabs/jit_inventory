"""
Opengear console server SNMP handling.

Opengear devices use OG-STATUSv2-MIB and OG-PRODUCTS-MIB for device information.
sysObjectID format: 1.3.6.1.4.1.25049.1.* (product OIDs)

References:
- Opengear Enterprise OID: 25049
- OG-STATUSv2-MIB: System status (serial, firmware)
- OG-PRODUCTS-MIB: Product model OIDs
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
    """Complete device inventory for Opengear devices."""

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


class OpengearHandler(VendorHandler):
    """Handler for Opengear console server devices."""

    ENTERPRISE_ID = 25049
    OID_PREFIX = "1.3.6.1.4.1.25049"

    # Opengear MIB OIDs for device information
    # Different firmware versions use different MIB branches
    OPENGEAR_OIDS = {
        # OG-STATUSv2-MIB (newer firmware, 4.x+)
        # ogSystem branch: 1.3.6.1.4.1.25049.17.1
        "sw_version": "1.3.6.1.4.1.25049.17.1.1",          # ogFirmwareVersion
        "serial_number": "1.3.6.1.4.1.25049.17.1.2",       # ogSerialNumber
        # OG-STATUS-MIB (older firmware)
        # ogStatus.ogBasicStatus branch: 1.3.6.1.4.1.25049.16.1
        "sw_version_alt": "1.3.6.1.4.1.25049.16.1.1",      # ogBasicFirmwareVersion
        "serial_number_alt": "1.3.6.1.4.1.25049.16.1.2",   # ogBasicSerialNumber
        # OG-HOST-MIB (some OM/CM devices)
        # ogHostSystem branch: 1.3.6.1.4.1.25049.2.1
        "serial_number_host": "1.3.6.1.4.1.25049.2.1.5",   # ogHostSerialNumber
        # Entity MIB fallbacks (index 1 = chassis)
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

    # Known Opengear model patterns from sysObjectID
    # Format: 1.3.6.1.4.1.25049.1.MODEL_ID (ogProducts branch)
    MODEL_OID_MAP = {
        # CM series (Console Manager)
        "1": "CM4001",
        "2": "CM4002",
        "3": "CM4008",
        "10": "CM41xx",
        "11": "CM71xx",
        "12": "CM7196",
        "31": "CMx86",
        "40": "CMS61xx",
        # SD series (Serial Device)
        "20": "SD4001",
        "21": "SD4002",
        "22": "SD4008",
        "23": "SD4001-DW",
        "24": "SD4002-DX",
        # CD series
        "30": "CD",
        # Lighthouse
        "41": "Lighthouse",
        "42": "Lighthouse 5",
        # IM series (Infrastructure Manager)
        "50": "IM4004",
        "60": "IM42xx",
        "61": "IM72xx",
        # KCS series
        "70": "KCS61xx",
        # ACM series (Advanced Console Manager)
        "80": "ACM500x",
        "81": "ACM550x",
        "90": "ACM700x",
        "91": "ACM70045",
        # OM series (Operations Manager) - newer products
        "100": "OM2200",
        "101": "OM2216",
        "102": "OM2224",
        "103": "OM2232",
        "104": "OM2248",
        # CM8100 series
        "110": "CM8116",
        "111": "CM8132",
        "112": "CM8148",
    }

    @property
    def vendor_name(self) -> str:
        return "opengear"

    @property
    def enterprise_id(self) -> int:
        return self.ENTERPRISE_ID

    def matches_sys_object_id(self, sys_object_id: str) -> bool:
        """Check if sysObjectID belongs to Opengear."""
        normalized = sys_object_id.lstrip(".")
        return normalized.startswith("1.3.6.1.4.1.25049")

    def identify_device_type(
        self, sys_object_id: str, sys_descr: str | None
    ) -> dict[str, str | None]:
        """Identify Opengear device type from sysDescr and sysObjectID."""
        result: dict[str, str | None] = {
            "device_type": "Console Appliance",
            "platform": "Opengear",
            "model": None,
        }

        # Try to extract model from sysObjectID first
        model_from_oid = self._parse_model_from_oid(sys_object_id)
        if model_from_oid:
            result["model"] = model_from_oid

        # If no model from OID, try sysDescr
        if not result["model"] and sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            if model_info.get("model"):
                result["model"] = model_info["model"]

        return result

    def _parse_model_from_sysdescr(self, sys_descr: str) -> dict[str, str | None]:
        """
        Extract model from sysDescr.

        Opengear sysDescr format examples:
        - "Opengear/IM7200 - 3.14.0 -- ..."
        - "Opengear CM7100"
        - "Linux opengear ..."
        """
        result: dict[str, str | None] = {
            "model": None,
        }

        # Extract model patterns
        model_patterns = [
            # OM series (Operations Manager)
            r"(OM\d{4})",
            # CM series
            r"(CM\d{4})",
            r"(CM8\d{3})",
            # IM series
            r"(IM\d{4})",
            # ACM series
            r"(ACM\d{4})",
            # SD series
            r"(SD\d{4})",
            # Lighthouse
            r"(Lighthouse\s*\d*)",
        ]

        for pattern in model_patterns:
            match = re.search(pattern, sys_descr, re.I)
            if match:
                result["model"] = match.group(1).upper()
                break

        return result

    def _parse_model_from_oid(self, sys_object_id: str) -> str | None:
        """
        Try to extract model from sysObjectID.

        Opengear sysObjectID format: 1.3.6.1.4.1.25049.1.MODEL_ID
        """
        match = re.search(r"25049\.1\.(\d+)", sys_object_id)
        if match:
            model_id = match.group(1)
            return self.MODEL_OID_MAP.get(model_id)

        return None

    def get_collection_oids(self) -> dict[str, str]:
        """Return OIDs to collect for Opengear devices."""
        return self.OPENGEAR_OIDS.copy()

    def parse_collected_data(
        self, raw_data: dict[str, Any], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """Parse Opengear-specific SNMP responses."""
        parsed: dict[str, Any] = {}

        # Serial number - try multiple sources (different MIB versions)
        serial = raw_data.get("serial_number", "")
        serial_alt = raw_data.get("serial_number_alt", "")
        serial_host = raw_data.get("serial_number_host", "")
        ent_serial = raw_data.get("ent_serial", "")

        if serial and serial.strip():
            parsed["serial_number"] = serial.strip()
        elif serial_alt and serial_alt.strip():
            parsed["serial_number"] = serial_alt.strip()
        elif serial_host and serial_host.strip():
            parsed["serial_number"] = serial_host.strip()
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
            model_match = re.search(r"((?:OM|IM|CM|ACM|SD)\d+)", ent_descr, re.I)
            if model_match:
                parsed["model"] = model_match.group(1).upper()
            else:
                parsed["model"] = ent_descr.strip()
        elif sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            parsed["model"] = model_info.get("model")
        else:
            parsed["model"] = None

        # Software version (firmware) - try multiple sources
        sw_version = raw_data.get("sw_version", "")
        sw_version_alt = raw_data.get("sw_version_alt", "")
        if sw_version and sw_version.strip():
            parsed["software_version"] = sw_version.strip()
        elif sw_version_alt and sw_version_alt.strip():
            parsed["software_version"] = sw_version_alt.strip()
        elif sys_descr:
            parsed["software_version"] = self._extract_version_from_sysdescr(sys_descr)
        else:
            parsed["software_version"] = None

        return parsed

    def _extract_version_from_sysdescr(self, sys_descr: str) -> str | None:
        """
        Extract firmware version from sysDescr.

        Example: "Opengear/IM7200 - 3.14.0 -- ..."
        """
        if not sys_descr:
            return None

        version_patterns = [
            r"-\s*(\d+\.\d+\.\d+)",
            r"version\s+(\d+\.\d+\.\d+)",
            r"v(\d+\.\d+\.\d+)",
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
        Opengear-specific override to handle devices that may not populate
        Entity MIB with serial numbers.

        Falls back to parsing version from sysDescr if Entity MIB doesn't have it.
        """
        # Call parent implementation first
        result = super().parse_basic_info_from_entity_walk(walk_results, sys_descr)

        # If no software version from Entity MIB, parse from sysDescr
        if not result.get("software_version") and sys_descr:
            result["software_version"] = self._extract_version_from_sysdescr(sys_descr)

        return result

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
