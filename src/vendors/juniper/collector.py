"""
Juniper Networks Junos OS SNMP handling.

Juniper devices use JUNIPER-MIB and JUNIPER-CHASSIS-DEFINES-MIB for device information.
sysObjectID format: 1.3.6.1.4.1.2636.1.1.1.2.* (product name OIDs)

References:
- Juniper Enterprise OID: 2636
- JUNIPER-MIB: Contains system info (serial, model, description)
- JUNIPER-CHASSIS-DEFINES-MIB: Product model OIDs
- sysDescr format: "Juniper Networks, Inc. srx340 internet router..."
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
    hardware_rev: str | None = None
    software_rev: str | None = None

    @property
    def class_name(self) -> str:
        """Return human-readable class name."""
        class_map = {
            1: "other",
            2: "unknown",
            3: "chassis",
            6: "power_supply",
            7: "fan",
            9: "module",
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
            "software_rev": self.software_rev,
        }


@dataclass
class DeviceInventory:
    """Complete device inventory for Juniper devices."""

    chassis: EntityComponent | None = None
    modules: list[EntityComponent] = field(default_factory=list)
    power_supplies: list[EntityComponent] = field(default_factory=list)
    fans: list[EntityComponent] = field(default_factory=list)
    all_components: list[EntityComponent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "chassis": self.chassis.to_dict() if self.chassis else None,
            "modules": [m.to_dict() for m in self.modules],
            "power_supplies": [p.to_dict() for p in self.power_supplies],
            "fans": [f.to_dict() for f in self.fans],
        }


class JuniperHandler(VendorHandler):
    """Handler for Juniper Networks devices running Junos OS."""

    ENTERPRISE_ID = 2636
    OID_PREFIX = "1.3.6.1.4.1.2636"

    # JUNIPER-MIB OIDs for device information (scalar OIDs)
    # Base: 1.3.6.1.4.1.2636.3.1
    JUNIPER_OIDS = {
        # jnxBoxDescr - The name, model, or detailed description of the box
        "model": "1.3.6.1.4.1.2636.3.1.2.0",
        # jnxBoxSerialNo - The serial number of the device
        "serial_number": "1.3.6.1.4.1.2636.3.1.3.0",
        # jnxBoxRevision - The revision of the device
        "hw_revision": "1.3.6.1.4.1.2636.3.1.4.0",
        # jnxBoxInstalled - Timestamp of last installation
        "installed": "1.3.6.1.4.1.2636.3.1.5.0",
        # Entity MIB fallbacks
        "ent_serial": "1.3.6.1.2.1.47.1.1.1.1.11.1",
        "ent_model": "1.3.6.1.2.1.47.1.1.1.1.13.1",
        "ent_descr": "1.3.6.1.2.1.47.1.1.1.1.2.1",
        "ent_sw_rev": "1.3.6.1.2.1.47.1.1.1.1.10.1",
    }

    # Entity MIB OID bases for walking (standard MIB)
    ENTITY_MIB_OIDS = {
        "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2",
        "entPhysicalClass": "1.3.6.1.2.1.47.1.1.1.1.5",
        "entPhysicalName": "1.3.6.1.2.1.47.1.1.1.1.7",
        "entPhysicalHardwareRev": "1.3.6.1.2.1.47.1.1.1.1.8",
        "entPhysicalSoftwareRev": "1.3.6.1.2.1.47.1.1.1.1.10",
        "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11",
        "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13",
    }

    # Known Juniper model patterns from sysObjectID
    # Format: 1.3.6.1.4.1.2636.1.1.1.2.MODEL_ID
    # Based on JUNIPER-CHASSIS-DEFINES-MIB
    MODEL_OID_MAP = {
        # SRX Series Firewalls
        "26": "SRX5800",
        "28": "SRX5600",
        "34": "SRX3600",
        "35": "SRX3400",
        "36": "SRX210",
        "39": "SRX240",
        "40": "SRX650",
        "64": "SRX100",
        "65": "SRX110",
        "86": "SRX550",
        "105": "SRX5400",
        "133": "SRX300",
        "134": "SRX320",
        "135": "SRX340",
        "136": "SRX345",
        "137": "SRX1500",
        "140": "SRX4600",
        "141": "SRX4800",
        "164": "SRX380",
        "577": "SRX1800",
        "580": "SRX220",
        "583": "SRX1600",
        "584": "SRX2300",
        "585": "SRX4300",
        # EX Series Switches
        "30": "EX3200",
        "31": "EX4200",
        "32": "EX8208",
        "33": "EX8216",
        "43": "EX2200",
        "44": "EX4500",
        "63": "EX4300",
        "74": "EX6210",
        "76": "EX3300",
        "92": "EX4550",
        "102": "EX9214",
        "103": "EX9208",
        "104": "EX9204",
        "109": "EX4600",
        "131": "EX3400",
        "132": "EX2300",
        "151": "EX9251",
        "156": "EX9253",
        "165": "EX4400",
        "169": "EX4100",
        "170": "EX4000",
        "508": "EX4650",
        # MX Series Routers
        "21": "MX960",
        "25": "MX480",
        "29": "MX240",
        "57": "MX80",
        "88": "MX40",
        "89": "MX10",
        "90": "MX5",
        "93": "MX2020",
        "97": "MX104",
        "99": "MX2010",
        "145": "MX2008",
        "146": "MXTSR80",
        "152": "MX150",
        "154": "MX10008",
        "155": "MX10016",
        "167": "MX304",
        "168": "MX10004",
        "592": "MX301",
        # QFX Series Switches
        "60": "QFX-Interconnect",
        "61": "QFX-Node",
        "62": "QFX-JVRE",
        "82": "QFX-Switch",
        "84": "QFX3000",
        "85": "QFX5000",
        "91": "QFXM-Interconnect",
        "100": "QFX3100",
        # T Series Routers
        "6": "T640",
        "7": "T320",
        "27": "T1600",
        # M Series Routers
        "1": "M40",
        "2": "M20",
        "3": "M160",
        "4": "M10",
        "5": "M5",
        "8": "M40e",
        "9": "M320",
        "10": "M7i",
        "11": "M10i",
        "18": "M120",
        # J Series Routers
        "13": "J2300",
        "14": "J4300",
        "15": "J6300",
        "19": "J4350",
        "20": "J6350",
        "22": "J4320",
        "23": "J2320",
        "24": "J2350",
    }

    @property
    def vendor_name(self) -> str:
        return "juniper"

    @property
    def enterprise_id(self) -> int:
        return self.ENTERPRISE_ID

    def matches_sys_object_id(self, sys_object_id: str) -> bool:
        """Check if sysObjectID belongs to Juniper Networks."""
        normalized = sys_object_id.lstrip(".")
        return normalized.startswith("1.3.6.1.4.1.2636")

    def identify_device_type(
        self, sys_object_id: str, sys_descr: str | None
    ) -> dict[str, str | None]:
        """Identify Juniper device type from sysDescr and sysObjectID."""
        result: dict[str, str | None] = {
            "device_type": "Network Device",
            "platform": "Junos",
            "model": None,
        }

        # Try to extract model from sysObjectID first (most reliable)
        model_from_oid = self._parse_model_from_oid(sys_object_id)
        if model_from_oid:
            result["model"] = model_from_oid
            result["device_type"] = self._get_device_type_from_model(model_from_oid)

        # If no model from OID, try sysDescr
        if not result["model"] and sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            if model_info.get("model"):
                result["model"] = model_info["model"]
            if model_info.get("device_type"):
                result["device_type"] = model_info["device_type"]

        return result

    def _parse_model_from_sysdescr(self, sys_descr: str) -> dict[str, str | None]:
        """
        Extract model and device type from sysDescr.

        Juniper sysDescr format examples:
        - "Juniper Networks, Inc. srx340 internet router, kernel JUNOS 21.4R3..."
        - "Juniper Networks, Inc. ex4300-48p Ethernet Switch, kernel JUNOS..."
        - "Juniper Networks, Inc. mx960 router, kernel JUNOS..."
        """
        result: dict[str, str | None] = {
            "model": None,
            "device_type": None,
        }

        sys_descr_lower = sys_descr.lower()

        # Extract model patterns from sysDescr
        model_patterns = [
            # SRX series (firewalls)
            r"(srx\d+[a-z0-9\-]*)",
            # EX series (switches)
            r"(ex\d+[a-z0-9\-]*)",
            # MX series (routers)
            r"(mx\d+[a-z0-9\-]*)",
            # QFX series (switches)
            r"(qfx\d+[a-z0-9\-]*)",
            # T series (routers)
            r"(t\d+[a-z0-9\-]*)",
            # M series (routers)
            r"\s(m\d+[a-z0-9\-]*)\s",
            # J series (routers)
            r"(j\d+[a-z0-9\-]*)",
        ]

        for pattern in model_patterns:
            match = re.search(pattern, sys_descr_lower)
            if match:
                result["model"] = match.group(1).upper()
                break

        # Determine device type
        if result["model"]:
            result["device_type"] = self._get_device_type_from_model(result["model"])
        elif "switch" in sys_descr_lower:
            result["device_type"] = "Switch"
        elif "router" in sys_descr_lower:
            result["device_type"] = "Router"
        elif "firewall" in sys_descr_lower or "internet router" in sys_descr_lower:
            # SRX devices often show as "internet router"
            result["device_type"] = "Firewall"

        return result

    def _get_device_type_from_model(self, model: str) -> str:
        """Determine device type from model string."""
        if not model:
            return "Network Device"

        model_upper = model.upper()

        if model_upper.startswith("SRX"):
            return "Firewall"
        elif model_upper.startswith("EX"):
            return "Switch"
        elif model_upper.startswith("QFX"):
            return "Switch"
        elif model_upper.startswith("MX"):
            return "Router"
        elif model_upper.startswith("T"):
            return "Router"
        elif model_upper.startswith("M"):
            return "Router"
        elif model_upper.startswith("J"):
            return "Router"
        else:
            return "Network Device"

    def _parse_model_from_oid(self, sys_object_id: str) -> str | None:
        """
        Try to extract model from sysObjectID.

        Juniper sysObjectID format: 1.3.6.1.4.1.2636.1.1.1.2.MODEL_ID
        """
        # Extract the model ID from the OID
        match = re.search(r"2636\.1\.1\.1\.2\.(\d+)", sys_object_id)
        if match:
            model_id = match.group(1)
            return self.MODEL_OID_MAP.get(model_id)

        return None

    def get_collection_oids(self) -> dict[str, str]:
        """Return OIDs to collect for Juniper devices."""
        return self.JUNIPER_OIDS.copy()

    def parse_collected_data(
        self, raw_data: dict[str, Any], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """Parse Juniper-specific SNMP responses."""
        parsed: dict[str, Any] = {}

        # Serial number: prefer JUNIPER-MIB, fallback to Entity MIB
        serial = raw_data.get("serial_number", "")
        ent_serial = raw_data.get("ent_serial", "")

        if serial and serial.strip():
            parsed["serial_number"] = serial.strip()
        elif ent_serial and ent_serial.strip():
            parsed["serial_number"] = ent_serial.strip()
        else:
            parsed["serial_number"] = None

        # Model: prefer JUNIPER-MIB jnxBoxDescr, fallback to Entity MIB or sysDescr
        model = raw_data.get("model", "")
        ent_model = raw_data.get("ent_model", "")
        ent_descr = raw_data.get("ent_descr", "")

        if model and model.strip():
            # jnxBoxDescr often has the full model description
            parsed["model"] = self._clean_model_string(model.strip())
        elif ent_model and ent_model.strip():
            parsed["model"] = ent_model.strip()
        elif ent_descr and ent_descr.strip():
            # Try to extract model from Entity description
            model_match = re.search(r"((?:SRX|EX|MX|QFX|T|M|J)\d+[A-Z0-9\-]*)", ent_descr, re.I)
            if model_match:
                parsed["model"] = model_match.group(1).upper()
            else:
                parsed["model"] = ent_descr.strip()
        elif sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            parsed["model"] = model_info.get("model")
        else:
            parsed["model"] = None

        # Software version: extract from sysDescr (JUNOS version)
        sw_version = raw_data.get("ent_sw_rev", "")
        if sw_version and sw_version.strip():
            parsed["software_version"] = sw_version.strip()
        elif sys_descr:
            parsed["software_version"] = self._extract_version_from_sysdescr(sys_descr)
        else:
            parsed["software_version"] = None

        # Additional Juniper-specific data (stored in metadata)
        parsed["metadata"] = {}

        if raw_data.get("hw_revision"):
            parsed["metadata"]["hw_revision"] = raw_data["hw_revision"].strip()

        # Clean up empty metadata
        if not parsed["metadata"]:
            del parsed["metadata"]

        return parsed

    def _clean_model_string(self, model: str) -> str:
        """Clean up model string from jnxBoxDescr."""
        # jnxBoxDescr might have format like "SRX340" or longer descriptions
        # Try to extract just the model number
        match = re.search(r"((?:SRX|EX|MX|QFX|T|M|J)\d+[A-Z0-9\-]*)", model, re.I)
        if match:
            return match.group(1).upper()
        return model

    def _extract_version_from_sysdescr(self, sys_descr: str) -> str | None:
        """
        Extract Junos version from sysDescr.

        Example: "Juniper Networks, Inc. srx340 internet router, kernel JUNOS 21.4R3-S5..."
        """
        if not sys_descr:
            return None

        # Junos version patterns
        version_patterns = [
            r"JUNOS\s+(\d+\.\d+[A-Z0-9\-\.]+)",
            r"Junos:\s+(\d+\.\d+[A-Z0-9\-\.]+)",
            r"Version\s+(\d+\.\d+[A-Z0-9\-\.]+)",
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
                elif oid_name == "entPhysicalClass":
                    try:
                        comp.entity_class = int(value_str) if value_str else None
                    except ValueError:
                        pass
                elif oid_name == "entPhysicalName":
                    comp.name = value_str
                elif oid_name == "entPhysicalHardwareRev":
                    comp.hardware_rev = value_str
                elif oid_name == "entPhysicalSoftwareRev":
                    comp.software_rev = value_str
                elif oid_name == "entPhysicalSerialNum":
                    comp.serial_number = value_str
                elif oid_name == "entPhysicalModelName":
                    comp.model_name = value_str

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

        return inventory

    def parse_basic_info_from_entity_walk(
        self, walk_results: dict[str, list[tuple[str, str]]], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """
        Juniper-specific override.

        Juniper devices have good Entity MIB support, but also have JUNIPER-MIB
        scalar OIDs for additional info.
        """
        # Call parent implementation
        result = super().parse_basic_info_from_entity_walk(walk_results, sys_descr)

        # If no software version from Entity MIB, try sysDescr
        if not result.get("software_version") and sys_descr:
            result["software_version"] = self._extract_version_from_sysdescr(sys_descr)

        return result
