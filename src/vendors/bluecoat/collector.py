"""
Blue Coat (Symantec/Broadcom) ProxySG SNMP handling.

Blue Coat devices use BLUECOAT-SG-PROXY-MIB for device information.
Now owned by Broadcom (formerly Symantec Enterprise).

sysObjectID format: 1.3.6.1.4.1.3417.* (Blue Coat Systems)

References:
- Blue Coat Enterprise OID: 3417
- BLUECOAT-SG-PROXY-MIB for ProxySG appliances
- sysDescr format: "Blue Coat SG600, Version: SGOS 6.7.5.1, Release id: 123456"
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
    """Complete device inventory for Blue Coat devices."""

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


class BlueCoatHandler(VendorHandler):
    """Handler for Blue Coat ProxySG devices."""

    ENTERPRISE_ID = 3417
    OID_PREFIX = "1.3.6.1.4.1.3417"

    # Blue Coat specific MIB OIDs
    # BLUECOAT-SG-PROXY-MIB
    BLUECOAT_OIDS = {
        # sgProxyConfig branch: 1.3.6.1.4.1.3417.2.11.1
        # sgProxySerialNumber
        "serial_number": "1.3.6.1.4.1.3417.2.11.1.4.0",
        # sgProxyVersion (SGOS version)
        "sw_version": "1.3.6.1.4.1.3417.2.11.1.1.0",
        # sgProxyPlatform (model/platform)
        "platform": "1.3.6.1.4.1.3417.2.11.1.3.0",
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

    # Known Blue Coat product OIDs
    # Format: 1.3.6.1.4.1.3417.1.1.PRODUCT_ID
    MODEL_OID_MAP = {
        # ProxySG appliances
        "1": "ProxySG",
        "2": "ProxySG",
        "35": "SG300",
        "36": "SG600",
        "37": "SG900",
        "38": "SG9000",
        "45": "SG-S200",
        "46": "SG-S400",
        "47": "SG-S500",
        "52": "ProxySG-VA",  # Virtual Appliance
    }

    @property
    def vendor_name(self) -> str:
        return "bluecoat"

    @property
    def enterprise_id(self) -> int:
        return self.ENTERPRISE_ID

    def matches_sys_object_id(self, sys_object_id: str) -> bool:
        """Check if sysObjectID belongs to Blue Coat."""
        normalized = sys_object_id.lstrip(".")
        return normalized.startswith("1.3.6.1.4.1.3417")

    def identify_device_type(
        self, sys_object_id: str, sys_descr: str | None
    ) -> dict[str, str | None]:
        """Identify Blue Coat device type from sysDescr and sysObjectID."""
        result: dict[str, str | None] = {
            "device_type": "Proxy",
            "platform": "SGOS",
            "model": None,
        }

        # Try to extract model from sysObjectID
        model_from_oid = self._parse_model_from_oid(sys_object_id)
        if model_from_oid:
            result["model"] = model_from_oid

        # Try to extract model from sysDescr (more accurate)
        if sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            if model_info.get("model"):
                result["model"] = model_info["model"]
            if model_info.get("device_type"):
                result["device_type"] = model_info["device_type"]

        return result

    def _parse_model_from_sysdescr(self, sys_descr: str) -> dict[str, str | None]:
        """
        Extract model from sysDescr.

        Blue Coat sysDescr format examples:
        - "Blue Coat SG600, Version: SGOS 6.7.5.1, Release id: 123456"
        - "Blue Coat SG9000, Version: SGOS 7.2.3.1"
        - "Blue Coat ProxySG 900, SGOS 6.5.10.1"
        - "Symantec ProxySG, Version: 7.3.1.1"
        """
        result: dict[str, str | None] = {
            "model": None,
            "device_type": None,
        }

        # Model patterns
        model_patterns = [
            # SG series
            r"(SG-?S?\d+)",
            r"(SG\d+)",
            # ProxySG with number
            r"ProxySG[\s\-]*(\d+)",
            # Virtual appliance
            r"(ProxySG-VA)",
            # Advanced Secure Gateway
            r"(ASG-S\d+)",
        ]

        for pattern in model_patterns:
            match = re.search(pattern, sys_descr, re.I)
            if match:
                model = match.group(1).upper()
                # Normalize model format
                if not model.startswith("SG") and not model.startswith("ASG"):
                    model = f"SG{model}"
                result["model"] = model
                break

        # Determine device type
        if result["model"]:
            if "VA" in result["model"]:
                result["device_type"] = "Virtual Proxy"
            elif "ASG" in result["model"]:
                result["device_type"] = "Advanced Secure Gateway"
            else:
                result["device_type"] = "Proxy Appliance"

        return result

    def _parse_model_from_oid(self, sys_object_id: str) -> str | None:
        """
        Try to extract model from sysObjectID.

        Blue Coat sysObjectID format: 1.3.6.1.4.1.3417.1.1.PRODUCT_ID
        """
        match = re.search(r"3417\.1\.1\.(\d+)", sys_object_id)
        if match:
            product_id = match.group(1)
            return self.MODEL_OID_MAP.get(product_id)
        return None

    def get_collection_oids(self) -> dict[str, str]:
        """Return OIDs to collect for Blue Coat devices."""
        return self.BLUECOAT_OIDS.copy()

    def parse_collected_data(
        self, raw_data: dict[str, Any], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """Parse Blue Coat-specific SNMP responses."""
        parsed: dict[str, Any] = {}

        # Serial number - try Blue Coat specific OID first
        serial = raw_data.get("serial_number", "")
        ent_serial = raw_data.get("ent_serial", "")

        if serial and serial.strip():
            parsed["serial_number"] = serial.strip()
        elif ent_serial and ent_serial.strip():
            parsed["serial_number"] = ent_serial.strip()
        else:
            parsed["serial_number"] = None

        # Model/Platform - try Blue Coat specific OID
        platform = raw_data.get("platform", "")
        ent_model = raw_data.get("ent_model", "")
        ent_descr = raw_data.get("ent_descr", "")

        if platform and platform.strip():
            parsed["model"] = platform.strip()
        elif ent_model and ent_model.strip():
            parsed["model"] = ent_model.strip()
        elif ent_descr and ent_descr.strip():
            parsed["model"] = ent_descr.strip()
        elif sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            parsed["model"] = model_info.get("model")
        else:
            parsed["model"] = None

        # Software version - try Blue Coat OID, then parse from sysDescr
        sw_version = raw_data.get("sw_version", "")

        if sw_version and sw_version.strip():
            parsed["software_version"] = sw_version.strip()
        elif sys_descr:
            parsed["software_version"] = self._extract_version_from_sysdescr(sys_descr)
        else:
            parsed["software_version"] = None

        return parsed

    def _extract_version_from_sysdescr(self, sys_descr: str) -> str | None:
        """
        Extract SGOS version from sysDescr.

        Examples:
        - "Blue Coat SG600, Version: SGOS 6.7.5.1, Release id: 123456"
        - "Version: 7.3.1.1"
        - "SGOS 6.5.10.1"
        """
        if not sys_descr:
            return None

        version_patterns = [
            r"SGOS\s+(\d+\.\d+[\.\d]*)",
            r"Version:\s*(?:SGOS\s+)?(\d+\.\d+[\.\d]*)",
            r"version\s+(\d+\.\d+[\.\d]*)",
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
        Blue Coat-specific override to handle parsing from sysDescr when
        Entity MIB doesn't have the required data.
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
