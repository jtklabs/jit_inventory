"""
F5 Networks BIG-IP SNMP handling.

F5 BIG-IP devices use F5-BIGIP-SYSTEM-MIB for device information.
sysObjectID format: 1.3.6.1.4.1.3375.2.1.3.4.* (product OIDs)

References:
- F5 Networks Enterprise OID: 3375
- F5-BIGIP-SYSTEM-MIB: Contains system info (serial, model, version)
- F5-BIGIP-COMMON-MIB: Common definitions
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
    """Complete device inventory for F5 BIG-IP devices."""

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


class F5Handler(VendorHandler):
    """Handler for F5 Networks BIG-IP devices."""

    ENTERPRISE_ID = 3375
    OID_PREFIX = "1.3.6.1.4.1.3375"

    # F5-BIGIP-SYSTEM-MIB OIDs for device information
    F5_OIDS = {
        # sysGeneralChassisSerialNum - Chassis serial number
        "serial_number": "1.3.6.1.4.1.3375.2.1.3.3.3.0",
        # sysProductVersion - Software version
        "sw_version": "1.3.6.1.4.1.3375.2.1.4.2.0",
        # sysProductName - Product name (e.g., "BIG-IP")
        "product_name": "1.3.6.1.4.1.3375.2.1.4.1.0",
        # sysGeneralHwName - Hardware model name
        "hw_name": "1.3.6.1.4.1.3375.2.1.3.3.1.0",
        # sysPlatformInfoMarketingName - Marketing name (e.g., "BIG-IP 4000")
        "marketing_name": "1.3.6.1.4.1.3375.2.1.3.5.2.0",
        # sysSystemName - OS name
        "os_name": "1.3.6.1.4.1.3375.2.1.6.1.0",
        # sysSystemRelease - OS release
        "os_release": "1.3.6.1.4.1.3375.2.1.6.3.0",
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

    # Known F5 model patterns
    MODEL_MAP = {
        "Z100": "BIG-IP Virtual Edition",
        "C109": "BIG-IP i2600",
        "C110": "BIG-IP i2800",
        "C112": "BIG-IP i4600",
        "C113": "BIG-IP 4000",
        "C114": "BIG-IP i4800",
        "C115": "BIG-IP i5600",
        "C116": "BIG-IP i5800",
        "C117": "BIG-IP i7600",
        "C118": "BIG-IP i7800",
        "C119": "BIG-IP i10600",
        "C120": "BIG-IP i10800",
        "C121": "BIG-IP i11600",
        "C122": "BIG-IP i11800",
        "C123": "BIG-IP i15600",
        "C124": "BIG-IP i15800",
        "D110": "BIG-IP 5000",
        "D111": "BIG-IP 5050",
        "D112": "BIG-IP 5200",
        "D113": "BIG-IP 5250",
        "D114": "BIG-IP 7000",
        "D115": "BIG-IP 7050",
        "D116": "BIG-IP 7200",
        "D117": "BIG-IP 7250",
        "E101": "BIG-IP 10000",
        "E102": "BIG-IP 10050",
        "E103": "BIG-IP 10200",
        "E104": "BIG-IP 10250",
        "E105": "BIG-IP 12000",
        "E106": "BIG-IP 12250",
    }

    @property
    def vendor_name(self) -> str:
        return "f5"

    @property
    def enterprise_id(self) -> int:
        return self.ENTERPRISE_ID

    def matches_sys_object_id(self, sys_object_id: str) -> bool:
        """Check if sysObjectID belongs to F5 Networks."""
        normalized = sys_object_id.lstrip(".")
        return normalized.startswith("1.3.6.1.4.1.3375")

    def identify_device_type(
        self, sys_object_id: str, sys_descr: str | None
    ) -> dict[str, str | None]:
        """Identify F5 device type from sysDescr and sysObjectID."""
        result: dict[str, str | None] = {
            "device_type": "Load Balancer",
            "platform": "TMOS",
            "model": None,
        }

        # Try to extract model from sysDescr
        if sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            if model_info.get("model"):
                result["model"] = model_info["model"]
            if model_info.get("device_type"):
                result["device_type"] = model_info["device_type"]

        return result

    def _parse_model_from_sysdescr(self, sys_descr: str) -> dict[str, str | None]:
        """
        Extract model and device type from sysDescr.

        F5 sysDescr format examples:
        - "BIG-IP Virtual Edition"
        - "Linux bigip1.example.com 3.10.0-862.14.4.el7.ve.x86_64..."
        """
        result: dict[str, str | None] = {
            "model": None,
            "device_type": None,
        }

        sys_descr_lower = sys_descr.lower()

        # Check for BIG-IP
        if "big-ip" in sys_descr_lower:
            model_match = re.search(r"(BIG-IP\s+\d+)", sys_descr, re.I)
            if model_match:
                result["model"] = model_match.group(1)
            elif "virtual" in sys_descr_lower:
                result["model"] = "BIG-IP VE"
            result["device_type"] = "Load Balancer"

        return result

    def get_collection_oids(self) -> dict[str, str]:
        """Return OIDs to collect for F5 devices."""
        return self.F5_OIDS.copy()

    def parse_collected_data(
        self, raw_data: dict[str, Any], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """Parse F5-specific SNMP responses."""
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

        # Model: prefer marketing name, then hw_name, then Entity MIB
        marketing_name = raw_data.get("marketing_name", "")
        hw_name = raw_data.get("hw_name", "")
        ent_model = raw_data.get("ent_model", "")

        if marketing_name and marketing_name.strip():
            parsed["model"] = marketing_name.strip()
        elif hw_name and hw_name.strip():
            # Map hardware code to friendly name
            hw_code = hw_name.strip()
            parsed["model"] = self.MODEL_MAP.get(hw_code, hw_code)
        elif ent_model and ent_model.strip():
            parsed["model"] = ent_model.strip()
        else:
            parsed["model"] = None

        # Software version
        sw_version = raw_data.get("sw_version", "")
        if sw_version and sw_version.strip():
            parsed["software_version"] = sw_version.strip()
        else:
            parsed["software_version"] = None

        # Additional metadata
        parsed["metadata"] = {}
        if raw_data.get("product_name"):
            parsed["metadata"]["product_name"] = raw_data["product_name"].strip()
        if raw_data.get("os_name"):
            parsed["metadata"]["os_name"] = raw_data["os_name"].strip()
        if raw_data.get("os_release"):
            parsed["metadata"]["os_release"] = raw_data["os_release"].strip()

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
