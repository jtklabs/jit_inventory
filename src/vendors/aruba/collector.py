"""
Aruba Networks wireless controller SNMP handling.

Aruba controllers use WLSX-SYSTEMEXT-MIB for controller info and
WLSX-WLAN-MIB for access point inventory.

sysObjectID format: 1.3.6.1.4.1.14823.1.1.* (controller products)

References:
- Aruba Enterprise OID: 14823
- WLSX-SYSTEMEXT-MIB: Controller system info (serial, model, SW version)
- WLSX-WLAN-MIB: Access point table (wlsxWlanAPTable)
- ARUBA-MIB: Product OIDs and AP models
"""
import re
from dataclasses import dataclass, field
from typing import Any

from src.vendors.base import VendorHandler


@dataclass
class AccessPoint:
    """Represents an access point registered to the controller."""

    mac_address: str
    name: str | None = None
    ip_address: str | None = None
    model: str | None = None
    serial_number: str | None = None
    group_name: str | None = None
    location: str | None = None
    status: str | None = None
    software_version: str | None = None

    @property
    def status_name(self) -> str:
        """Return human-readable status."""
        status_map = {
            "1": "up",
            "2": "down",
        }
        return status_map.get(str(self.status), self.status or "unknown")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "mac_address": self.mac_address,
            "name": self.name,
            "ip_address": self.ip_address,
            "model": self.model,
            "serial_number": self.serial_number,
            "group_name": self.group_name,
            "location": self.location,
            "status": self.status_name,
            "software_version": self.software_version,
        }


@dataclass
class EntityComponent:
    """Represents a physical component (card/module) in the controller."""

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
        }


@dataclass
class DeviceInventory:
    """Complete device inventory for Aruba wireless controllers."""

    chassis: EntityComponent | None = None
    modules: list[EntityComponent] = field(default_factory=list)
    power_supplies: list[EntityComponent] = field(default_factory=list)
    fans: list[EntityComponent] = field(default_factory=list)
    access_points: list[AccessPoint] = field(default_factory=list)
    all_components: list[EntityComponent] = field(default_factory=list)

    @property
    def ap_count(self) -> int:
        """Return number of access points."""
        return len(self.access_points)

    @property
    def ap_up_count(self) -> int:
        """Return number of APs that are up."""
        return sum(1 for ap in self.access_points if ap.status_name == "up")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "chassis": self.chassis.to_dict() if self.chassis else None,
            "modules": [m.to_dict() for m in self.modules],
            "power_supplies": [p.to_dict() for p in self.power_supplies],
            "fans": [f.to_dict() for f in self.fans],
            "access_points": [ap.to_dict() for ap in self.access_points],
            "ap_count": self.ap_count,
            "ap_up_count": self.ap_up_count,
        }


class ArubaHandler(VendorHandler):
    """Handler for Aruba Networks wireless controllers."""

    ENTERPRISE_ID = 14823
    OID_PREFIX = "1.3.6.1.4.1.14823"

    # WLSX-SYSTEMEXT-MIB OIDs for controller information
    # Base: 1.3.6.1.4.1.14823.2.2.1.2.1
    ARUBA_OIDS = {
        # wlsxSysExtHostname - Controller hostname
        "hostname": "1.3.6.1.4.1.14823.2.2.1.2.1.2.0",
        # wlsxSysExtModelName - Controller model
        "model": "1.3.6.1.4.1.14823.2.2.1.2.1.3.0",
        # wlsxSysExtHwVersion - Hardware version
        "hw_version": "1.3.6.1.4.1.14823.2.2.1.2.1.27.0",
        # wlsxSysExtSwVersion - Software version
        "sw_version": "1.3.6.1.4.1.14823.2.2.1.2.1.28.0",
        # wlsxSysExtSerialNumber - Serial number
        "serial_number": "1.3.6.1.4.1.14823.2.2.1.2.1.29.0",
        # wlsxSysExtSwitchBaseMacaddress - Base MAC address
        "base_mac": "1.3.6.1.4.1.14823.2.2.1.2.1.7.0",
        # wlsxSysExtLicenseSerialNumber - License serial
        "license_serial": "1.3.6.1.4.1.14823.2.2.1.2.1.11.0",
        # wlsxSwitchTotalNumAccessPoints - Total AP count
        "ap_count": "1.3.6.1.4.1.14823.2.2.1.1.3.1.0",
        # Entity MIB fallbacks
        "ent_serial": "1.3.6.1.2.1.47.1.1.1.1.11.1",
        "ent_model": "1.3.6.1.2.1.47.1.1.1.1.13.1",
        "ent_descr": "1.3.6.1.2.1.47.1.1.1.1.2.1",
    }

    # WLSX-WLAN-MIB OIDs for AP table (wlsxWlanAPTable) - ArubaOS 6.x+
    # Base: 1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1
    # Indexed by AP MAC address (6 octets)
    AP_TABLE_OIDS = {
        "wlanAPMacAddress": "1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.1",
        "wlanAPIpAddress": "1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.2",
        "wlanAPName": "1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.3",
        "wlanAPGroupName": "1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.4",
        "wlanAPModel": "1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.5",
        "wlanAPSerialNumber": "1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.6",
        "wlanAPLocation": "1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.14",
        "wlanAPStatus": "1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.19",
        "wlanAPSwVersion": "1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.34",
    }

    # WLSX-SWITCH-MIB OIDs for AP table (wlsxSwitchAccessPointTable) - Older/alternative
    # Base: 1.3.6.1.4.1.14823.2.2.1.1.3.3.1
    # Indexed by BSSID MAC address (6 octets)
    # Note: This table has less detail but may work on older controllers
    AP_TABLE_ALT_OIDS = {
        "apBSSID": "1.3.6.1.4.1.14823.2.2.1.1.3.3.1.1",
        "apESSID": "1.3.6.1.4.1.14823.2.2.1.1.3.3.1.2",
        "apIpAddress": "1.3.6.1.4.1.14823.2.2.1.1.3.3.1.5",
        "apLocation": "1.3.6.1.4.1.14823.2.2.1.1.3.3.1.9",
    }

    # Total AP count OID (useful for verification)
    # wlsxSwitchTotalNumAccessPoints
    AP_COUNT_OID = "1.3.6.1.4.1.14823.2.2.1.1.3.1.0"

    # Entity MIB OID bases for walking (standard MIB)
    ENTITY_MIB_OIDS = {
        "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2",
        "entPhysicalClass": "1.3.6.1.2.1.47.1.1.1.1.5",
        "entPhysicalName": "1.3.6.1.2.1.47.1.1.1.1.7",
        "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11",
        "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13",
    }

    # Known Aruba controller models from sysObjectID
    # Format: 1.3.6.1.4.1.14823.1.1.MODEL_ID
    MODEL_OID_MAP = {
        # Mobility Controllers
        "1": "A5000",
        "2": "A2400",
        "3": "A800",
        "4": "A6000",
        "5": "A2400E",
        "7": "A2800",
        "9": "MC-3200",
        "10": "A650",
        "11": "A651",
        "13": "S3500",
        "16": "S2500",
        "17": "A7210",
        "18": "A7220",
        "19": "A7240",
        "20": "S1500-12P",
        "21": "S1500-24P",
        "22": "S1500-48P",
        "23": "7005",
        "24": "7010",
        "25": "7030",
        "26": "7205",
        "27": "7210",
        "28": "7220",
        "29": "7240",
        "30": "7240XM",
        "31": "S2500-24P",
        "32": "S2500-24T",
        "33": "S2500-48P",
        "34": "S2500-48T",
        "35": "S2500-24F",
        "36": "S3500-24P",
        "37": "S3500-24T",
        "38": "S3500-48P",
        "39": "S3500-48T",
        "40": "S3500-24F",
        "48": "7008",
        "49": "7024",
        "50": "9004",
        "51": "MC-VA",
        "52": "7280",
        "53": "9004-LTE",
        # 9000 series
        "60": "9240",
        "61": "9012",
        "62": "9004-LTE-US",
        "63": "9004-LTE-JP",
    }

    @property
    def vendor_name(self) -> str:
        return "aruba"

    @property
    def enterprise_id(self) -> int:
        return self.ENTERPRISE_ID

    def matches_sys_object_id(self, sys_object_id: str) -> bool:
        """
        Check if sysObjectID belongs to Aruba Networks (excluding ClearPass).

        ClearPass uses 1.3.6.1.4.1.14823.1.6.* and should be handled by ClearPassHandler.
        """
        normalized = sys_object_id.lstrip(".")
        # Exclude ClearPass (1.6.*)
        if normalized.startswith("1.3.6.1.4.1.14823.1.6"):
            return False
        return normalized.startswith("1.3.6.1.4.1.14823")

    def identify_device_type(
        self, sys_object_id: str, sys_descr: str | None
    ) -> dict[str, str | None]:
        """Identify Aruba device type from sysDescr and sysObjectID."""
        result: dict[str, str | None] = {
            "device_type": "Wireless Controller",
            "platform": "ArubaOS",
            "model": None,
        }

        # Try to extract model from sysDescr first
        if sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            if model_info.get("model"):
                result["model"] = model_info["model"]
            if model_info.get("device_type"):
                result["device_type"] = model_info["device_type"]
            if model_info.get("platform"):
                result["platform"] = model_info["platform"]

        # If no model from sysDescr, try sysObjectID
        if not result["model"]:
            model_from_oid = self._parse_model_from_oid(sys_object_id)
            if model_from_oid:
                result["model"] = model_from_oid

        return result

    def _parse_model_from_sysdescr(self, sys_descr: str) -> dict[str, str | None]:
        """
        Extract model and device type from sysDescr.

        Aruba sysDescr format examples:
        - "ArubaOS (MODEL: Aruba7210), Version 8.6.0.0"
        - "ArubaOS (MODEL: Aruba7005-US), Version 8.3.0.0"
        - "Aruba JL071A 2930F-24G-4SFP+ Switch"  (CX switches)
        """
        result: dict[str, str | None] = {
            "model": None,
            "device_type": None,
            "platform": None,
        }

        sys_descr_lower = sys_descr.lower()

        # Check for ArubaOS wireless controller
        if "arubaos" in sys_descr_lower:
            result["platform"] = "ArubaOS"
            result["device_type"] = "Wireless Controller"

            # Extract model from "(MODEL: ArubaXXXX)"
            model_match = re.search(r"\(MODEL:\s*([^)]+)\)", sys_descr, re.I)
            if model_match:
                model = model_match.group(1).strip()
                # Clean up model name (remove "Aruba" prefix if present)
                model = re.sub(r"^Aruba\s*", "", model, flags=re.I)
                result["model"] = model

        # Check for Aruba Instant (virtual controller on AP)
        elif "aruba instant" in sys_descr_lower:
            result["platform"] = "Aruba Instant"
            result["device_type"] = "Wireless Controller"

        # Check for ArubaOS-CX switches
        elif "arubaos-cx" in sys_descr_lower:
            result["platform"] = "ArubaOS-CX"
            result["device_type"] = "Switch"
            # Extract model
            model_match = re.search(r"(\d{4}[A-Z0-9\-]*)", sys_descr)
            if model_match:
                result["model"] = model_match.group(1)

        # Check for Aruba switches (non-CX)
        elif "aruba" in sys_descr_lower and "switch" in sys_descr_lower:
            result["platform"] = "ArubaOS-Switch"
            result["device_type"] = "Switch"

        return result

    def _parse_model_from_oid(self, sys_object_id: str) -> str | None:
        """
        Try to extract model from sysObjectID.

        Aruba sysObjectID format: 1.3.6.1.4.1.14823.1.1.MODEL_ID (controllers)
                                  1.3.6.1.4.1.14823.1.2.MODEL_ID (APs)
        """
        # Try controller products first (1.1.X)
        match = re.search(r"14823\.1\.1\.(\d+)", sys_object_id)
        if match:
            model_id = match.group(1)
            return self.MODEL_OID_MAP.get(model_id)

        # Try AP products (1.2.X) - return generic "AP" with model ID
        match = re.search(r"14823\.1\.2\.(\d+)", sys_object_id)
        if match:
            return f"AP-{match.group(1)}"

        return None

    def get_collection_oids(self) -> dict[str, str]:
        """Return OIDs to collect for Aruba controllers."""
        return self.ARUBA_OIDS.copy()

    def parse_collected_data(
        self, raw_data: dict[str, Any], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """Parse Aruba-specific SNMP responses."""
        parsed: dict[str, Any] = {}

        # Serial number: prefer WLSX-SYSTEMEXT-MIB, fallback to Entity MIB
        serial = raw_data.get("serial_number", "")
        ent_serial = raw_data.get("ent_serial", "")

        if serial and serial.strip():
            parsed["serial_number"] = serial.strip()
        elif ent_serial and ent_serial.strip():
            parsed["serial_number"] = ent_serial.strip()
        else:
            parsed["serial_number"] = None

        # Model: prefer WLSX-SYSTEMEXT-MIB, fallback to Entity MIB or sysDescr
        model = raw_data.get("model", "")
        ent_model = raw_data.get("ent_model", "")

        if model and model.strip():
            parsed["model"] = model.strip()
        elif ent_model and ent_model.strip():
            parsed["model"] = ent_model.strip()
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

        # Additional Aruba-specific data
        parsed["metadata"] = {}

        if raw_data.get("hw_version"):
            parsed["metadata"]["hw_version"] = raw_data["hw_version"].strip()
        if raw_data.get("base_mac"):
            parsed["metadata"]["base_mac"] = raw_data["base_mac"].strip()
        if raw_data.get("license_serial"):
            parsed["metadata"]["license_serial"] = raw_data["license_serial"].strip()
        if raw_data.get("ap_count"):
            try:
                parsed["metadata"]["ap_count"] = int(raw_data["ap_count"])
            except ValueError:
                pass

        # Clean up empty metadata
        if not parsed["metadata"]:
            del parsed["metadata"]

        return parsed

    def _extract_version_from_sysdescr(self, sys_descr: str) -> str | None:
        """
        Extract ArubaOS version from sysDescr.

        Example: "ArubaOS (MODEL: Aruba7210), Version 8.6.0.0"
        """
        if not sys_descr:
            return None

        version_patterns = [
            r"Version\s+(\d+\.\d+\.\d+\.\d+)",
            r"Version\s+(\d+\.\d+\.\d+)",
            r"ArubaOS\s+(\d+\.\d+\.\d+)",
        ]

        for pattern in version_patterns:
            match = re.search(pattern, sys_descr, re.I)
            if match:
                return match.group(1)

        return None

    def get_entity_mib_oids(self) -> dict[str, str]:
        """Return Entity MIB OID bases for walking."""
        return self.ENTITY_MIB_OIDS.copy()

    def get_ap_table_oids(self) -> dict[str, str]:
        """Return AP table OID bases for walking (WLSX-WLAN-MIB)."""
        return self.AP_TABLE_OIDS.copy()

    def get_ap_table_alt_oids(self) -> dict[str, str]:
        """Return alternate AP table OID bases for walking (WLSX-SWITCH-MIB)."""
        return self.AP_TABLE_ALT_OIDS.copy()

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

    def parse_ap_table(
        self, walk_results: dict[str, list[tuple[str, str]]]
    ) -> list[AccessPoint]:
        """
        Parse WLSX-WLAN-MIB AP table walk results into AccessPoint objects.

        The AP table is indexed by the AP MAC address (6 octets), so the OID
        suffix is the MAC address in decimal form: .x.x.x.x.x.x

        Args:
            walk_results: Dict mapping OID name to list of (full_oid, value) tuples

        Returns:
            List of AccessPoint objects
        """
        access_points: dict[str, AccessPoint] = {}

        def get_mac_index(oid: str, base_oid: str) -> str | None:
            """Extract MAC address index from OID suffix."""
            suffix = oid.replace(base_oid + ".", "")
            parts = suffix.split(".")
            if len(parts) >= 6:
                try:
                    # Convert decimal octets to MAC address format
                    mac_parts = [int(p) for p in parts[:6]]
                    return ":".join(f"{p:02x}" for p in mac_parts)
                except ValueError:
                    return None
            return None

        def parse_ip_address(value: str | None) -> str | None:
            """Convert SNMP IP address value to dotted-decimal string."""
            if not value:
                return None
            # If it's already a valid IP format, return it
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
                return value
            # SNMP may return IP as raw bytes - try to convert
            # Check if it looks like raw bytes (4 characters, non-printable)
            if len(value) == 4:
                try:
                    octets = [ord(c) for c in value]
                    return ".".join(str(o) for o in octets)
                except (TypeError, ValueError):
                    pass
            # Try interpreting as bytes object representation
            if value.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in value):
                try:
                    # Hex string like "0a0b0c0d" or "0x0a0b0c0d"
                    hex_str = value.replace("0x", "")
                    if len(hex_str) == 8:
                        octets = [int(hex_str[i:i+2], 16) for i in range(0, 8, 2)]
                        return ".".join(str(o) for o in octets)
                except (ValueError, IndexError):
                    pass
            return value  # Return as-is if we can't parse it

        for oid_name, results in walk_results.items():
            base_oid = self.AP_TABLE_OIDS.get(oid_name)
            if not base_oid:
                continue

            for full_oid, value in results:
                mac = get_mac_index(full_oid, base_oid)
                if mac is None:
                    continue

                if mac not in access_points:
                    access_points[mac] = AccessPoint(mac_address=mac)

                ap = access_points[mac]
                value_str = str(value).strip() if value else None

                if oid_name == "wlanAPIpAddress":
                    ap.ip_address = parse_ip_address(value_str)
                elif oid_name == "wlanAPName":
                    ap.name = value_str
                elif oid_name == "wlanAPGroupName":
                    ap.group_name = value_str
                elif oid_name == "wlanAPModel":
                    ap.model = value_str
                elif oid_name == "wlanAPSerialNumber":
                    ap.serial_number = value_str
                elif oid_name == "wlanAPLocation":
                    ap.location = value_str
                elif oid_name == "wlanAPStatus":
                    ap.status = value_str
                elif oid_name == "wlanAPSwVersion":
                    ap.software_version = value_str

        # Sort by AP name for consistent display
        ap_list = list(access_points.values())
        ap_list.sort(key=lambda x: x.name or x.mac_address)

        return ap_list

    def parse_ap_table_alt(
        self, walk_results: dict[str, list[tuple[str, str]]]
    ) -> list[AccessPoint]:
        """
        Parse WLSX-SWITCH-MIB AP table (wlsxSwitchAccessPointTable) as fallback.

        This table has less detail but may work on older controllers.
        Indexed by BSSID MAC address.

        Args:
            walk_results: Dict mapping OID name to list of (full_oid, value) tuples

        Returns:
            List of AccessPoint objects (with limited info)
        """
        access_points: dict[str, AccessPoint] = {}

        def get_mac_index(oid: str, base_oid: str) -> str | None:
            """Extract MAC address index from OID suffix."""
            suffix = oid.replace(base_oid + ".", "")
            parts = suffix.split(".")
            if len(parts) >= 6:
                try:
                    mac_parts = [int(p) for p in parts[:6]]
                    return ":".join(f"{p:02x}" for p in mac_parts)
                except ValueError:
                    return None
            return None

        def parse_ip_address(value: str | None) -> str | None:
            """Convert SNMP IP address value to dotted-decimal string."""
            if not value:
                return None
            # If it's already a valid IP format, return it
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
                return value
            # SNMP may return IP as raw bytes - try to convert
            if len(value) == 4:
                try:
                    octets = [ord(c) for c in value]
                    return ".".join(str(o) for o in octets)
                except (TypeError, ValueError):
                    pass
            return value

        for oid_name, results in walk_results.items():
            base_oid = self.AP_TABLE_ALT_OIDS.get(oid_name)
            if not base_oid:
                continue

            for full_oid, value in results:
                mac = get_mac_index(full_oid, base_oid)
                if mac is None:
                    continue

                if mac not in access_points:
                    access_points[mac] = AccessPoint(mac_address=mac)

                ap = access_points[mac]
                value_str = str(value).strip() if value else None

                if oid_name == "apIpAddress":
                    ap.ip_address = parse_ip_address(value_str)
                elif oid_name == "apESSID":
                    # Use ESSID as name if we don't have a real name
                    if not ap.name:
                        ap.name = value_str
                elif oid_name == "apLocation":
                    ap.location = value_str

        ap_list = list(access_points.values())
        ap_list.sort(key=lambda x: x.name or x.mac_address)

        return ap_list

    def parse_basic_info_from_entity_walk(
        self, walk_results: dict[str, list[tuple[str, str]]], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """
        Aruba-specific override.

        Aruba controllers may have limited Entity MIB support - most data
        comes from WLSX-SYSTEMEXT-MIB scalar OIDs.
        """
        result = super().parse_basic_info_from_entity_walk(walk_results, sys_descr)

        if not result.get("software_version") and sys_descr:
            result["software_version"] = self._extract_version_from_sysdescr(sys_descr)

        return result
