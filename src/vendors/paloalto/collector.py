"""
Palo Alto Networks PAN-OS-specific SNMP handling.

Palo Alto firewalls use PAN-COMMON-MIB and PAN-PRODUCTS-MIB for device information.
sysObjectID format: 1.3.6.1.4.1.25461.2.3.* (varies by model)

References:
- Palo Alto Enterprise OID: 25461
- PAN-COMMON-MIB: Contains system info (serial, model, SW version)
- PAN-PRODUCTS-MIB: Product model OIDs
- sysDescr format: "Palo Alto Networks MODEL series firewall"
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
    """Complete device inventory for Palo Alto firewalls."""

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


class PaloAltoHandler(VendorHandler):
    """Handler for Palo Alto Networks firewall devices."""

    ENTERPRISE_ID = 25461
    OID_PREFIX = "1.3.6.1.4.1.25461"

    # PAN-COMMON-MIB OIDs for device information
    # These are scalar OIDs (single values, not tables)
    PALOALTO_OIDS = {
        # panSysSwVersion - PAN-OS software version
        "sw_version": "1.3.6.1.4.1.25461.2.1.2.1.1.0",
        # panSysHwVersion - Hardware version/model
        "hw_version": "1.3.6.1.4.1.25461.2.1.2.1.2.0",
        # panSysSerialNumber - Device serial number
        "serial_number": "1.3.6.1.4.1.25461.2.1.2.1.3.0",
        # panSysAppVersion - App-ID version
        "app_version": "1.3.6.1.4.1.25461.2.1.2.1.4.0",
        # panSysAvVersion - Antivirus version
        "av_version": "1.3.6.1.4.1.25461.2.1.2.1.5.0",
        # panSysThreatVersion - Threat prevention version
        "threat_version": "1.3.6.1.4.1.25461.2.1.2.1.6.0",
        # panSysUrlFilteringVersion - URL filtering version
        "url_version": "1.3.6.1.4.1.25461.2.1.2.1.7.0",
        # panSysGlobalProtectClientVersion - GlobalProtect version
        "gp_version": "1.3.6.1.4.1.25461.2.1.2.1.8.0",
        # panSysHAState - HA state (active/passive/etc)
        "ha_state": "1.3.6.1.4.1.25461.2.1.2.1.11.0",
        # panSysHAPeerState - HA peer state
        "ha_peer_state": "1.3.6.1.4.1.25461.2.1.2.1.12.0",
        # panSysHAMode - HA mode (disabled/active-passive/active-active)
        "ha_mode": "1.3.6.1.4.1.25461.2.1.2.1.13.0",
        # Entity MIB index 1 (fallback for basic info)
        "ent_serial": "1.3.6.1.2.1.47.1.1.1.1.11.1",
        "ent_model": "1.3.6.1.2.1.47.1.1.1.1.13.1",
        "ent_descr": "1.3.6.1.2.1.47.1.1.1.1.2.1",
    }

    # Entity MIB OID bases for walking (standard MIB - limited on PAN-OS)
    ENTITY_MIB_OIDS = {
        "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2",
        "entPhysicalClass": "1.3.6.1.2.1.47.1.1.1.1.5",
        "entPhysicalName": "1.3.6.1.2.1.47.1.1.1.1.7",
        "entPhysicalHardwareRev": "1.3.6.1.2.1.47.1.1.1.1.8",
        "entPhysicalSoftwareRev": "1.3.6.1.2.1.47.1.1.1.1.10",
        "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11",
        "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13",
    }

    # Known Palo Alto model patterns from sysObjectID
    # Format: 1.3.6.1.4.1.25461.2.3.MODEL_ID
    # Based on PAN-PRODUCTS-MIB
    MODEL_OID_MAP = {
        # PA-200 series (end of life)
        "1": "PA-200",
        # PA-220 series
        "22": "PA-220",
        # PA-400 series
        "61": "PA-410",
        "62": "PA-415",
        "63": "PA-440",
        "64": "PA-450",
        "65": "PA-460",
        # PA-500 series (end of life)
        "5": "PA-500",
        # PA-800 series
        "29": "PA-820",
        "30": "PA-850",
        # PA-3000 series
        "17": "PA-3020",
        "18": "PA-3050",
        "19": "PA-3060",
        "31": "PA-3220",
        "32": "PA-3250",
        "33": "PA-3260",
        # PA-3400 series
        "66": "PA-3410",
        "67": "PA-3420",
        "68": "PA-3430",
        "69": "PA-3440",
        # PA-5000 series (older)
        "9": "PA-5020",
        "10": "PA-5050",
        "11": "PA-5060",
        # PA-5200 series
        "34": "PA-5220",
        "35": "PA-5250",
        "36": "PA-5260",
        "37": "PA-5280",
        # PA-5400 series
        "70": "PA-5410",
        "71": "PA-5420",
        "72": "PA-5430",
        "73": "PA-5440",
        "74": "PA-5445",
        # PA-7000 series (chassis)
        "27": "PA-7050",
        "28": "PA-7080",
        # VM-Series
        "50": "VM-50",
        "100": "VM-100",
        "200": "VM-200",
        "300": "VM-300",
        "500": "VM-500",
        "700": "VM-700",
        "1000": "VM-1000-HV",
        # CN-Series (container)
        "80": "CN-Series",
        # Panorama management
        "23": "Panorama",
        "24": "M-100",
        "38": "M-200",
        "39": "M-500",
        "40": "M-600",
        # WF-500 (WildFire appliance)
        "60": "WF-500",
    }

    # HA state mapping
    HA_STATE_MAP = {
        "0": "disabled",
        "1": "initial",
        "2": "active",
        "3": "passive",
        "4": "tentative",
        "5": "non-functional",
        "6": "suspended",
        "7": "active-primary",
        "8": "active-secondary",
    }

    # HA mode mapping
    HA_MODE_MAP = {
        "0": "disabled",
        "1": "active-passive",
        "2": "active-active",
    }

    @property
    def vendor_name(self) -> str:
        return "paloalto"

    @property
    def enterprise_id(self) -> int:
        return self.ENTERPRISE_ID

    def matches_sys_object_id(self, sys_object_id: str) -> bool:
        """Check if sysObjectID belongs to Palo Alto Networks."""
        normalized = sys_object_id.lstrip(".")
        return normalized.startswith("1.3.6.1.4.1.25461")

    def identify_device_type(
        self, sys_object_id: str, sys_descr: str | None
    ) -> dict[str, str | None]:
        """Identify Palo Alto device type from sysDescr and sysObjectID."""
        result: dict[str, str | None] = {
            "device_type": "Firewall",  # Default - most Palo Alto devices are firewalls
            "platform": "PAN-OS",
            "model": None,
        }

        # Try to extract model from sysDescr first (most reliable)
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
                # Update device type based on model
                result["device_type"] = self._get_device_type_from_model(model_from_oid)

        return result

    def _parse_model_from_sysdescr(self, sys_descr: str) -> dict[str, str | None]:
        """
        Extract model and device type from sysDescr.

        Palo Alto sysDescr format examples:
        - "Palo Alto Networks PA-3260 series firewall"
        - "Palo Alto Networks PA-VM series firewall"
        - "Palo Alto Networks PA-5220"
        - "Palo Alto Networks Panorama"
        - "Palo Alto Networks M-500 Appliance"
        """
        result: dict[str, str | None] = {
            "model": None,
            "device_type": None,
            "platform": None,
        }

        sys_descr_lower = sys_descr.lower()

        # Check for Panorama (management platform)
        if "panorama" in sys_descr_lower:
            result["device_type"] = "Management"
            result["platform"] = "Panorama"
            # Try to extract model (M-100, M-500, etc.)
            match = re.search(r"(M-\d+)", sys_descr, re.I)
            if match:
                result["model"] = match.group(1).upper()
            else:
                result["model"] = "Panorama"
            return result

        # Check for WildFire appliance
        if "wildfire" in sys_descr_lower or "wf-" in sys_descr_lower:
            result["device_type"] = "Security Appliance"
            match = re.search(r"(WF-\d+)", sys_descr, re.I)
            if match:
                result["model"] = match.group(1).upper()
            return result

        # Extract model patterns
        model_patterns = [
            # PA-XXXX series (hardware firewalls)
            r"(PA-\d+[A-Z0-9\-]*)",
            # VM-Series (virtual firewalls)
            r"(VM-\d+[A-Z0-9\-]*)",
            # CN-Series (container firewalls)
            r"(CN-[A-Z]+)",
            # M-Series (Panorama appliances)
            r"(M-\d+)",
        ]

        for pattern in model_patterns:
            match = re.search(pattern, sys_descr, re.I)
            if match:
                result["model"] = match.group(1).upper()
                break

        # Determine device type from model
        if result["model"]:
            result["device_type"] = self._get_device_type_from_model(result["model"])

        return result

    def _get_device_type_from_model(self, model: str) -> str:
        """Determine device type from model string."""
        if not model:
            return "Firewall"

        model_upper = model.upper()

        if model_upper.startswith("VM-"):
            return "Virtual Firewall"
        elif model_upper.startswith("CN-"):
            return "Container Firewall"
        elif model_upper.startswith("M-") or "PANORAMA" in model_upper:
            return "Management"
        elif model_upper.startswith("WF-"):
            return "Security Appliance"
        elif model_upper.startswith("PA-7"):
            return "Chassis Firewall"  # PA-7000 series are modular chassis
        else:
            return "Firewall"

    def _parse_model_from_oid(self, sys_object_id: str) -> str | None:
        """
        Try to extract model from sysObjectID.

        Palo Alto sysObjectID format: 1.3.6.1.4.1.25461.2.3.MODEL_ID
        """
        # Extract the model ID from the OID
        match = re.search(r"25461\.2\.3\.(\d+)", sys_object_id)
        if match:
            model_id = match.group(1)
            return self.MODEL_OID_MAP.get(model_id)

        return None

    def get_collection_oids(self) -> dict[str, str]:
        """Return OIDs to collect for Palo Alto devices."""
        return self.PALOALTO_OIDS.copy()

    def parse_collected_data(
        self, raw_data: dict[str, Any], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """Parse Palo Alto-specific SNMP responses."""
        parsed: dict[str, Any] = {}

        # Serial number: prefer PAN-COMMON-MIB, fallback to Entity MIB
        serial = raw_data.get("serial_number", "")
        ent_serial = raw_data.get("ent_serial", "")

        if serial and serial.strip():
            parsed["serial_number"] = serial.strip()
        elif ent_serial and ent_serial.strip():
            parsed["serial_number"] = ent_serial.strip()
        else:
            parsed["serial_number"] = None

        # Model: prefer PAN-COMMON-MIB hw_version, fallback to Entity MIB or sysDescr
        hw_version = raw_data.get("hw_version", "")
        ent_model = raw_data.get("ent_model", "")
        ent_descr = raw_data.get("ent_descr", "")

        if hw_version and hw_version.strip():
            parsed["model"] = hw_version.strip()
        elif ent_model and ent_model.strip():
            parsed["model"] = ent_model.strip()
        elif ent_descr and ent_descr.strip():
            # Entity description might have model info
            model_match = re.search(r"(PA-\d+[A-Z0-9\-]*)", ent_descr, re.I)
            if model_match:
                parsed["model"] = model_match.group(1).upper()
            else:
                parsed["model"] = ent_descr.strip()
        elif sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            parsed["model"] = model_info.get("model")
        else:
            parsed["model"] = None

        # Software version: from PAN-COMMON-MIB
        sw_version = raw_data.get("sw_version", "")
        if sw_version and sw_version.strip():
            parsed["software_version"] = sw_version.strip()
        elif sys_descr:
            parsed["software_version"] = self._extract_version_from_sysdescr(sys_descr)
        else:
            parsed["software_version"] = None

        # Additional Palo Alto-specific data (stored in metadata)
        parsed["metadata"] = {}

        # Content versions
        if raw_data.get("app_version"):
            parsed["metadata"]["app_version"] = raw_data["app_version"].strip()
        if raw_data.get("av_version"):
            parsed["metadata"]["av_version"] = raw_data["av_version"].strip()
        if raw_data.get("threat_version"):
            parsed["metadata"]["threat_version"] = raw_data["threat_version"].strip()
        if raw_data.get("url_version"):
            parsed["metadata"]["url_version"] = raw_data["url_version"].strip()
        if raw_data.get("gp_version"):
            parsed["metadata"]["gp_version"] = raw_data["gp_version"].strip()

        # HA information
        ha_state = raw_data.get("ha_state", "")
        ha_mode = raw_data.get("ha_mode", "")
        ha_peer = raw_data.get("ha_peer_state", "")

        if ha_mode and ha_mode.strip():
            parsed["metadata"]["ha_mode"] = self.HA_MODE_MAP.get(
                ha_mode.strip(), ha_mode.strip()
            )
        if ha_state and ha_state.strip():
            parsed["metadata"]["ha_state"] = self.HA_STATE_MAP.get(
                ha_state.strip(), ha_state.strip()
            )
        if ha_peer and ha_peer.strip():
            parsed["metadata"]["ha_peer_state"] = self.HA_STATE_MAP.get(
                ha_peer.strip(), ha_peer.strip()
            )

        # Clean up empty metadata
        if not parsed["metadata"]:
            del parsed["metadata"]

        return parsed

    def _extract_version_from_sysdescr(self, sys_descr: str) -> str | None:
        """
        Extract PAN-OS version from sysDescr.

        PAN-OS version is typically not in sysDescr, but we try common patterns.
        """
        if not sys_descr:
            return None

        # PAN-OS version patterns
        version_patterns = [
            r"PAN-OS\s+(\d+\.\d+\.\d+[a-zA-Z0-9\-]*)",
            r"version\s+(\d+\.\d+\.\d+[a-zA-Z0-9\-]*)",
            r"(\d+\.\d+\.\d+[a-zA-Z0-9\-]*)\s+",
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

        Note: Palo Alto has limited Entity MIB support compared to Cisco/Arista.
        Most hardware info comes from PAN-COMMON-MIB scalar OIDs.

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
            elif comp.entity_class == 6:  # Power supply
                inventory.power_supplies.append(comp)
            elif comp.entity_class == 7:  # Fan
                inventory.fans.append(comp)

        return inventory

    def parse_basic_info_from_entity_walk(
        self, walk_results: dict[str, list[tuple[str, str]]], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """
        Palo Alto-specific override.

        Palo Alto devices have limited Entity MIB support.
        Most data comes from scalar OIDs collected via get_collection_oids().
        """
        # Call parent implementation
        result = super().parse_basic_info_from_entity_walk(walk_results, sys_descr)

        # If no software version from Entity MIB, try sysDescr
        if not result.get("software_version") and sys_descr:
            result["software_version"] = self._extract_version_from_sysdescr(sys_descr)

        return result
