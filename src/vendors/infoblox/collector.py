"""
Infoblox NIOS SNMP handling.

Infoblox DDI appliances use IB-PLATFORMONE-MIB for device information.
sysObjectID format: 1.3.6.1.4.1.7779.1.* (product OIDs)

References:
- Infoblox Enterprise OID: 7779
- IB-PLATFORMONE-MIB: Contains platform info (serial, hardware type)
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
    """Complete device inventory for Infoblox appliances."""

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


class InfobloxHandler(VendorHandler):
    """Handler for Infoblox DDI (DNS/DHCP/IPAM) appliances."""

    ENTERPRISE_ID = 7779
    OID_PREFIX = "1.3.6.1.4.1.7779"

    # IB-PLATFORMONE-MIB OIDs for device information
    # Base: 1.3.6.1.4.1.7779.3.1.1.2.1
    INFOBLOX_OIDS = {
        # ibHardwareType - Hardware platform type
        "hw_type": "1.3.6.1.4.1.7779.3.1.1.2.1.4.0",
        # ibSerialNumber - Device serial number
        "serial_number": "1.3.6.1.4.1.7779.3.1.1.2.1.6.0",
        # ibNiosVersion - NIOS version
        "nios_version": "1.3.6.1.4.1.7779.3.1.1.2.1.7.0",
        # ibHardwareId - Hardware ID
        "hw_id": "1.3.6.1.4.1.7779.3.1.1.2.1.8.0",
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

    # Known Infoblox model patterns from sysObjectID
    # Format: 1.3.6.1.4.1.7779.1.MODEL_ID
    MODEL_OID_MAP = {
        "1004": "Trinzic Virtual",
        "1202": "Trinzic 1050",
        "1302": "Trinzic 1050",
        "1303": "Trinzic 1550",
        "1401": "Trinzic 810",
        "1402": "Trinzic 820",
        "1403": "Trinzic 1410",
        "1404": "Trinzic 1420",
        "1405": "Trinzic 2210",
        "1406": "Trinzic 2220",
        "1407": "PT-1400",
        "1410": "Trinzic 805",
        "1411": "Trinzic 815",
        "1412": "Trinzic 2210",
        "1413": "Trinzic 2220",
        "1414": "Trinzic 4010",
        "1415": "Trinzic 4020",
        "1421": "Trinzic 4010",
        "1422": "Trinzic 4020",
        "1423": "Trinzic 4000",
        "1424": "Trinzic 4000",
        "1501": "ND-805",
        "1502": "ND-1405",
        "1503": "ND-2205",
        "1504": "ND-4005",
    }

    @property
    def vendor_name(self) -> str:
        return "infoblox"

    @property
    def enterprise_id(self) -> int:
        return self.ENTERPRISE_ID

    def matches_sys_object_id(self, sys_object_id: str) -> bool:
        """Check if sysObjectID belongs to Infoblox."""
        normalized = sys_object_id.lstrip(".")
        return normalized.startswith("1.3.6.1.4.1.7779")

    def identify_device_type(
        self, sys_object_id: str, sys_descr: str | None
    ) -> dict[str, str | None]:
        """Identify Infoblox device type from sysDescr and sysObjectID."""
        result: dict[str, str | None] = {
            "device_type": "IPAM",
            "platform": "NIOS",
            "model": None,
        }

        # Try to extract model from sysObjectID
        model_from_oid = self._parse_model_from_oid(sys_object_id)
        if model_from_oid:
            result["model"] = model_from_oid

        # Try to extract from sysDescr if no model yet
        if not result["model"] and sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            if model_info.get("model"):
                result["model"] = model_info["model"]

        return result

    def _parse_model_from_sysdescr(self, sys_descr: str) -> dict[str, str | None]:
        """
        Extract model from sysDescr.

        Infoblox sysDescr format examples:
        - "Infoblox-1410"
        - "IB-VM-810"
        """
        result: dict[str, str | None] = {
            "model": None,
        }

        model_patterns = [
            r"(Infoblox-\d+)",
            r"(IB-\d+)",
            r"(IB-VM-\d+)",
            r"(Trinzic\s+\d+)",
            r"(ND-\d+)",
            r"(PT-\d+)",
        ]

        for pattern in model_patterns:
            match = re.search(pattern, sys_descr, re.I)
            if match:
                result["model"] = match.group(1)
                break

        return result

    def _parse_model_from_oid(self, sys_object_id: str) -> str | None:
        """
        Try to extract model from sysObjectID.

        Infoblox sysObjectID format: 1.3.6.1.4.1.7779.1.MODEL_ID
        """
        match = re.search(r"7779\.1\.(\d+)", sys_object_id)
        if match:
            model_id = match.group(1)
            return self.MODEL_OID_MAP.get(model_id)

        return None

    def get_collection_oids(self) -> dict[str, str]:
        """Return OIDs to collect for Infoblox devices."""
        return self.INFOBLOX_OIDS.copy()

    def parse_collected_data(
        self, raw_data: dict[str, Any], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """Parse Infoblox-specific SNMP responses."""
        parsed: dict[str, Any] = {}

        # Serial number
        serial = raw_data.get("serial_number", "")
        ent_serial = raw_data.get("ent_serial", "")

        if serial and serial.strip():
            parsed["serial_number"] = serial.strip()
        elif ent_serial and ent_serial.strip():
            parsed["serial_number"] = ent_serial.strip()
        else:
            parsed["serial_number"] = None

        # Model: prefer ibHardwareType
        hw_type = raw_data.get("hw_type", "")
        ent_model = raw_data.get("ent_model", "")

        if hw_type and hw_type.strip():
            parsed["model"] = hw_type.strip()
        elif ent_model and ent_model.strip():
            parsed["model"] = ent_model.strip()
        elif sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            parsed["model"] = model_info.get("model")
        else:
            parsed["model"] = None

        # Software version (NIOS version)
        nios_version = raw_data.get("nios_version", "")
        if nios_version and nios_version.strip():
            parsed["software_version"] = nios_version.strip()
        else:
            parsed["software_version"] = None

        # Additional metadata
        parsed["metadata"] = {}
        if raw_data.get("hw_id"):
            parsed["metadata"]["hardware_id"] = raw_data["hw_id"].strip()

        if not parsed["metadata"]:
            del parsed["metadata"]

        return parsed

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
