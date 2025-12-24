"""
Check Point firewall SNMP handling.

Check Point devices use CHECKPOINT-MIB for device information.
sysObjectID format: 1.3.6.1.4.1.2620.1.6.* (SVN info)

References:
- Check Point Enterprise OID: 2620
- CHECKPOINT-MIB: Contains firewall, VPN, HA info
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
    """Complete device inventory for Check Point firewalls."""

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


class CheckpointHandler(VendorHandler):
    """Handler for Check Point firewall devices."""

    ENTERPRISE_ID = 2620
    OID_PREFIX = "1.3.6.1.4.1.2620"

    # CHECKPOINT-MIB OIDs for device information
    CHECKPOINT_OIDS = {
        # svnVersion - SVN version
        "svn_version": "1.3.6.1.4.1.2620.1.6.4.1.0",
        # svnApplianceProductName - Appliance model
        "appliance_model": "1.3.6.1.4.1.2620.1.6.16.7.0",
        # svnApplianceSerialNumber - Serial number
        "serial_number": "1.3.6.1.4.1.2620.1.6.16.3.0",
        # svnApplianceManufacturer - Manufacturer
        "manufacturer": "1.3.6.1.4.1.2620.1.6.16.9.0",
        # fwProdName - Firewall product name
        "fw_prod_name": "1.3.6.1.4.1.2620.1.1.21.0",
        # fwVerMajor - Major version
        "fw_ver_major": "1.3.6.1.4.1.2620.1.1.22.0",
        # fwVerMinor - Minor version
        "fw_ver_minor": "1.3.6.1.4.1.2620.1.1.23.0",
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

    # Known Check Point appliance models
    APPLIANCE_MODELS = {
        # SMB appliances
        "600": "600 Appliance",
        "700": "700 Appliance",
        "910": "910 Appliance",
        "1100": "1100 Appliance",
        "1200R": "1200R Appliance",
        "1400": "1400 Appliance",
        "1500": "1500 Appliance",
        # Enterprise appliances
        "3100": "3100 Appliance",
        "3200": "3200 Appliance",
        "5000": "5000 Appliance",
        "5100": "5100 Appliance",
        "5200": "5200 Appliance",
        "5400": "5400 Appliance",
        "5600": "5600 Appliance",
        "5800": "5800 Appliance",
        "5900": "5900 Appliance",
        "6200": "6200 Appliance",
        "6500": "6500 Appliance",
        "6600": "6600 Appliance",
        "6700": "6700 Appliance",
        "6800": "6800 Appliance",
        "6900": "6900 Appliance",
        # High-end appliances
        "15400": "15400 Appliance",
        "15600": "15600 Appliance",
        "16000": "16000 Appliance",
        "23500": "23500 Appliance",
        "23800": "23800 Appliance",
        "23900": "23900 Appliance",
        "26000": "26000 Appliance",
        "28000": "28000 Appliance",
        # Maestro Hyperscale
        "MHO-140": "Maestro Hyperscale Orchestrator 140",
        "MHO-170": "Maestro Hyperscale Orchestrator 170",
        "MHO-175": "Maestro Hyperscale Orchestrator 175",
    }

    @property
    def vendor_name(self) -> str:
        return "checkpoint"

    @property
    def enterprise_id(self) -> int:
        return self.ENTERPRISE_ID

    def matches_sys_object_id(self, sys_object_id: str) -> bool:
        """Check if sysObjectID belongs to Check Point."""
        normalized = sys_object_id.lstrip(".")
        return normalized.startswith("1.3.6.1.4.1.2620")

    def identify_device_type(
        self, sys_object_id: str, sys_descr: str | None
    ) -> dict[str, str | None]:
        """Identify Check Point device type from sysDescr and sysObjectID."""
        result: dict[str, str | None] = {
            "device_type": "Firewall",
            "platform": "Gaia",
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
        Extract model from sysDescr.

        Check Point sysDescr format examples:
        - "Check Point 5600 Appliance"
        - "Linux checkpoint-fw 3.10.0-957.12.1cpx86_64 ..."
        """
        result: dict[str, str | None] = {
            "model": None,
            "device_type": None,
        }

        sys_descr_lower = sys_descr.lower()

        # Check for appliance models in sysDescr
        model_patterns = [
            r"Check\s*Point\s+(\d+[A-Z]*)\s+Appliance",
            r"(MHO-\d+)",
            r"Maestro.*Orchestrator\s+(\d+)",
            r"(\d{4,5})\s+Appliance",
        ]

        for pattern in model_patterns:
            match = re.search(pattern, sys_descr, re.I)
            if match:
                model_num = match.group(1)
                result["model"] = self.APPLIANCE_MODELS.get(
                    model_num, f"Appliance {model_num}"
                )
                break

        # Determine device type
        if "maestro" in sys_descr_lower or "orchestrator" in sys_descr_lower:
            result["device_type"] = "Hyperscale Orchestrator"
        elif "management" in sys_descr_lower:
            result["device_type"] = "Management Server"

        return result

    def get_collection_oids(self) -> dict[str, str]:
        """Return OIDs to collect for Check Point devices."""
        return self.CHECKPOINT_OIDS.copy()

    def parse_collected_data(
        self, raw_data: dict[str, Any], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """Parse Check Point-specific SNMP responses."""
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

        # Model: prefer appliance_model
        appliance_model = raw_data.get("appliance_model", "")
        ent_model = raw_data.get("ent_model", "")

        if appliance_model and appliance_model.strip():
            parsed["model"] = appliance_model.strip()
        elif ent_model and ent_model.strip():
            parsed["model"] = ent_model.strip()
        elif sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            parsed["model"] = model_info.get("model")
        else:
            parsed["model"] = None

        # Software version: combine major.minor or use svn_version
        svn_version = raw_data.get("svn_version", "")
        fw_ver_major = raw_data.get("fw_ver_major", "")
        fw_ver_minor = raw_data.get("fw_ver_minor", "")

        if svn_version and svn_version.strip():
            parsed["software_version"] = svn_version.strip()
        elif fw_ver_major and fw_ver_minor:
            parsed["software_version"] = f"R{fw_ver_major.strip()}.{fw_ver_minor.strip()}"
        elif fw_ver_major:
            parsed["software_version"] = f"R{fw_ver_major.strip()}"
        else:
            parsed["software_version"] = None

        # Additional metadata
        parsed["metadata"] = {}
        if raw_data.get("fw_prod_name"):
            parsed["metadata"]["product_name"] = raw_data["fw_prod_name"].strip()
        if raw_data.get("manufacturer"):
            parsed["metadata"]["manufacturer"] = raw_data["manufacturer"].strip()

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
