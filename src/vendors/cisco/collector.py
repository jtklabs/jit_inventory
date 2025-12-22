"""
Cisco-specific SNMP handling for IOS, IOS-XE, NX-OS, and ASA devices.
"""
import re
from dataclasses import dataclass, field
from typing import Any

from src.vendors.base import VendorHandler, ENTITY_MIB_OIDS, ENTITY_CLASS_CHASSIS, ENTITY_CLASS_STACK


@dataclass
class EntityComponent:
    """Represents a physical component from Entity MIB."""

    index: int
    description: str | None = None
    vendor_type: str | None = None
    contained_in: int | None = None
    entity_class: int | None = None  # 3=chassis, 5=container, 9=module, 10=port
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
            "entity_class": self.entity_class,
            "class_name": self.class_name,
            "contained_in": self.contained_in,
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
class License:
    """Represents a Cisco license from CISCO-LICENSE-MGMT-MIB."""

    index: int
    feature_name: str | None = None
    license_type: int | None = None  # 1=demo, 2=extension, 3=grace, 4=permanent, etc.
    end_date: str | None = None  # DateAndTime format
    validity_period_remaining: int | None = None  # seconds remaining
    max_count: int | None = None  # max usage count (0 = uncounted)
    count_remaining: int | None = None
    status: int | None = None  # 1=inUse, 2=notInUse, etc.

    @property
    def type_name(self) -> str:
        """Return human-readable license type."""
        type_map = {
            1: "demo",
            2: "extension",
            3: "grace_period",
            4: "permanent",
            5: "paid_subscription",
            6: "evaluation_subscription",
            7: "extension_subscription",
            8: "evaluation_right_to_use",
            9: "right_to_use",
            10: "permanent_right_to_use",
        }
        return type_map.get(self.license_type or 0, "unknown")

    @property
    def status_name(self) -> str:
        """Return human-readable status."""
        status_map = {
            1: "in_use",
            2: "not_in_use",
            3: "none",
            4: "unknown",
        }
        return status_map.get(self.status or 0, "unknown")

    @property
    def is_permanent(self) -> bool:
        """Check if this is a permanent license."""
        return self.license_type in (4, 10)  # permanent or permanent_right_to_use

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "index": self.index,
            "feature_name": self.feature_name,
            "license_type": self.type_name,
            "status": self.status_name,
            "end_date": self.end_date,
            "validity_remaining_seconds": self.validity_period_remaining,
            "max_count": self.max_count,
            "count_remaining": self.count_remaining,
            "is_permanent": self.is_permanent,
        }


@dataclass
class DeviceInventory:
    """Complete device inventory with modules and stack info."""

    chassis: EntityComponent | None = None
    modules: list[EntityComponent] = field(default_factory=list)
    power_supplies: list[EntityComponent] = field(default_factory=list)
    fans: list[EntityComponent] = field(default_factory=list)
    stack_members: list[EntityComponent] = field(default_factory=list)
    all_components: list[EntityComponent] = field(default_factory=list)
    licenses: list[License] = field(default_factory=list)

    @property
    def is_stack(self) -> bool:
        """Check if this is a stacked switch."""
        return len(self.stack_members) > 1

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "is_stack": self.is_stack,
            "stack_count": len(self.stack_members) if self.is_stack else 0,
            "chassis": self.chassis.to_dict() if self.chassis else None,
            "modules": [m.to_dict() for m in self.modules],
            "power_supplies": [p.to_dict() for p in self.power_supplies],
            "fans": [f.to_dict() for f in self.fans],
            "stack_members": [s.to_dict() for s in self.stack_members],
            "licenses": [lic.to_dict() for lic in self.licenses],
            "all_components": [c.to_dict() for c in self.all_components],
        }


class CiscoHandler(VendorHandler):
    """Handler for Cisco network devices."""

    ENTERPRISE_ID = 9
    OID_PREFIX = "1.3.6.1.4.1.9"

    # Cisco-specific OIDs for data collection
    CISCO_OIDS = {
        # Entity MIB index 1 (chassis/stack - preferred for modern devices)
        "ent_serial": "1.3.6.1.2.1.47.1.1.1.1.11.1",
        "ent_model": "1.3.6.1.2.1.47.1.1.1.1.13.1",
        "ent_sw_rev": "1.3.6.1.2.1.47.1.1.1.1.10.1",
        "ent_descr": "1.3.6.1.2.1.47.1.1.1.1.2.1",
        # Entity MIB index 1001 (first switch in stack - often has exact model)
        "ent_serial_1001": "1.3.6.1.2.1.47.1.1.1.1.11.1001",
        "ent_model_1001": "1.3.6.1.2.1.47.1.1.1.1.13.1001",
        # Entity MIB index 1000 (alternate first switch location)
        "ent_serial_1000": "1.3.6.1.2.1.47.1.1.1.1.11.1000",
        "ent_model_1000": "1.3.6.1.2.1.47.1.1.1.1.13.1000",
        # OLD-CISCO-CHASSIS-MIB (fallback for older devices)
        "chassis_serial": "1.3.6.1.4.1.9.3.6.3.0",
        # CISCO-IMAGE-MIB
        "image_string": "1.3.6.1.4.1.9.9.25.1.1.1.2.2",
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

    # CISCO-LICENSE-MGMT-MIB OIDs for walking (clmgmtLicenseInfoTable)
    # Table is indexed by entPhysicalIndex.clmgmtLicenseStoreIndex.clmgmtLicenseIndex
    LICENSE_MIB_OIDS = {
        "clmgmtLicenseFeatureName": "1.3.6.1.4.1.9.9.543.1.2.3.1.3",
        "clmgmtLicenseType": "1.3.6.1.4.1.9.9.543.1.2.3.1.4",
        "clmgmtLicenseEndDate": "1.3.6.1.4.1.9.9.543.1.2.3.1.8",
        "clmgmtLicenseValidityPeriodRemaining": "1.3.6.1.4.1.9.9.543.1.2.3.1.9",
        "clmgmtLicenseMaxUsageCount": "1.3.6.1.4.1.9.9.543.1.2.3.1.11",
        "clmgmtLicenseUsageCountRemaining": "1.3.6.1.4.1.9.9.543.1.2.3.1.12",
        "clmgmtLicenseStatus": "1.3.6.1.4.1.9.9.543.1.2.3.1.16",
    }

    @property
    def vendor_name(self) -> str:
        return "cisco"

    @property
    def enterprise_id(self) -> int:
        return self.ENTERPRISE_ID

    def matches_sys_object_id(self, sys_object_id: str) -> bool:
        """Check if sysObjectID belongs to Cisco."""
        normalized = sys_object_id.lstrip(".")
        return normalized.startswith("1.3.6.1.4.1.9")

    def identify_device_type(
        self, sys_object_id: str, sys_descr: str | None
    ) -> dict[str, str | None]:
        """Identify Cisco device type from sysDescr (preferred) then sysObjectID."""
        result: dict[str, str | None] = {
            "device_type": None,
            "platform": None,
            "model": None,
        }

        # First, try to extract info from sysDescr - this is most accurate
        if sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            if model_info.get("model"):
                result["model"] = model_info["model"]
            if model_info.get("platform"):
                result["platform"] = model_info["platform"]
            if model_info.get("device_type"):
                result["device_type"] = model_info["device_type"]

        # If we got useful info from sysDescr (model, or platform/type), we're done
        if result["model"] or (result["platform"] and result["device_type"]):
            return result

        # Fallback: use sysObjectID patterns (less accurate but works for unknown devices)
        result.update(self._identify_from_oid(sys_object_id, sys_descr))

        return result

    def _parse_model_from_sysdescr(self, sys_descr: str) -> dict[str, str | None]:
        """Extract model, platform, and device type from sysDescr."""
        result: dict[str, str | None] = {
            "model": None,
            "platform": None,
            "device_type": None,
        }

        sys_descr_lower = sys_descr.lower()

        # Detect platform - order matters, check more specific patterns first
        if "nx-os" in sys_descr_lower or "nxos" in sys_descr_lower:
            result["platform"] = "NX-OS"
            result["device_type"] = "Switch"
        elif "ios-xe" in sys_descr_lower or "ios xe" in sys_descr_lower or "iosxe" in sys_descr_lower:
            result["platform"] = "IOS-XE"
        elif "isr software" in sys_descr_lower:
            # ISR Software with Linux kernel = IOS-XE on ISR routers
            result["platform"] = "IOS-XE"
            result["device_type"] = "Router"
        elif "firepower threat defense" in sys_descr_lower or "ftd" in sys_descr_lower:
            result["platform"] = "FTD"
            result["device_type"] = "Firewall"
        elif "firepower" in sys_descr_lower or "fxos" in sys_descr_lower:
            result["platform"] = "FXOS"
            result["device_type"] = "Firewall"
        elif "adaptive security" in sys_descr_lower or "asa software" in sys_descr_lower:
            result["platform"] = "ASA"
            result["device_type"] = "Firewall"
        elif "ios software" in sys_descr_lower or "cisco ios software" in sys_descr_lower:
            result["platform"] = "IOS"
            # IOS can be switch or router - check for router indicators
            if any(x in sys_descr_lower for x in ["router", "isr", "asr", "c1900", "c2900", "c3900", "c4000"]):
                result["device_type"] = "Router"

        # Extract model - ordered by specificity
        model_patterns = [
            # Nexus patterns
            (r"Nexus\s*(\d{4})", "Nexus {}"),
            (r"(N\d{1,2}K-C\d+[A-Z0-9\-]*)", "{}"),
            # ISR routers - check before Catalyst since ISR Software pattern is more specific
            (r"(ISR\d{4}[A-Z0-9\-]*)", "{}"),
            (r"ISR Software.*CISCO(\d{4}[A-Z0-9\-/]*)", "ISR {}"),
            (r"cisco (ISR\d+[A-Z0-9\-/]*)", "{}"),
            # Router with CISCO model number (ISR1900/2900/3900/4000 series)
            (r"[Rr]outer.*CISCO(\d{4}[A-Z0-9\-/]*)", "ISR {}"),
            (r"CISCO(\d{4}[A-Z0-9\-/]*).*[Rr]outer", "ISR {}"),
            # Catalyst 9000 series
            (r"(C9\d{3}[A-Z0-9\-]*)", "Catalyst {}"),
            # Catalyst with WS- prefix
            (r"(WS-C\d{4}[A-Z0-9\-]*)", "{}"),
            # Catalyst from software name (e.g., "C3750 Software") - but not if Router in description
            (r"(C\d{4}[A-Z]?)\s+Software(?!.*[Rr]outer)", "Catalyst {}"),
            # Generic Catalyst
            (r"Catalyst\s+(\d{4}[A-Z0-9\-]*)", "Catalyst {}"),
            # ISR fallback - CISCO with 4-digit number
            (r"CISCO(\d{4}[A-Z0-9\-/]*)\s", "ISR {}"),
            # ASR routers
            (r"(ASR\d{4}[A-Z0-9\-]*)", "{}"),
            (r"(ASR-\d{4}[A-Z0-9\-]*)", "{}"),
            # ASA firewalls
            (r"(ASA\d{4}[A-Z0-9\-]*)", "{}"),
            (r"Cisco Adaptive Security Appliance.*?(55\d{2}[A-Z0-9\-]*)", "ASA {}"),
            # Firepower
            (r"(FPR-?\d{4}[A-Z0-9\-]*)", "{}"),
            (r"Firepower\s+(\d{4}[A-Z0-9\-]*)", "Firepower {}"),
            (r"(FMC\d{4}[A-Z0-9\-]*)", "{}"),
            # Wireless controllers
            (r"(AIR-CT\d{4}[A-Z0-9\-]*)", "{}"),
            (r"(C9800[A-Z0-9\-]*)", "{}"),
        ]

        for pattern, format_str in model_patterns:
            match = re.search(pattern, sys_descr, re.I)
            if match:
                model_part = match.group(1).upper()
                result["model"] = format_str.format(model_part)
                break

        # Infer device type from model if not already set
        if result["model"] and not result["device_type"]:
            model_lower = result["model"].lower()
            if any(x in model_lower for x in ["catalyst", "nexus", "ws-c", "n9k", "n7k", "n5k", "n3k"]):
                result["device_type"] = "Switch"
            elif any(x in model_lower for x in ["isr", "asr", "cisco2", "cisco3", "cisco4"]):
                result["device_type"] = "Router"
            elif any(x in model_lower for x in ["asa", "firepower", "fpr", "fmc", "ftd"]):
                result["device_type"] = "Firewall"
            elif any(x in model_lower for x in ["air-ct", "c9800", "wlc"]):
                result["device_type"] = "Wireless Controller"

        # If we still don't have device_type, infer from sysDescr content
        if not result["device_type"]:
            if "router" in sys_descr_lower:
                result["device_type"] = "Router"
            elif "switch" in sys_descr_lower:
                result["device_type"] = "Switch"

        return result

    def _identify_from_oid(
        self, sys_object_id: str, sys_descr: str | None
    ) -> dict[str, str | None]:
        """Fallback identification from sysObjectID patterns."""
        result: dict[str, str | None] = {
            "device_type": None,
            "platform": None,
            "model": None,
        }

        # Common sysObjectID patterns - only used as fallback
        oid_patterns = {
            r"\.9\.1\.(516|517|518|519)$": ("Switch", "IOS", None),
            r"\.9\.1\.(559|560)$": ("Switch", "IOS", None),
            r"\.9\.1\.(696|697|698|699)$": ("Switch", "IOS", None),
            r"\.9\.1\.(633|634|635|636)$": ("Switch", "IOS", None),
            r"\.9\.1\.(928|929|930|931)$": ("Switch", "IOS", None),
            r"\.9\.1\.(1208|1209|1210|1211|1212)$": ("Switch", "IOS-XE", None),
            r"\.9\.1\.(2066|2067|2068|2069|2070)$": ("Switch", "IOS-XE", None),
            r"\.9\.1\.(2489|2490|2491)$": ("Switch", "IOS-XE", None),
            r"\.9\.1\.(1041|1042|1043|1044|1045)$": ("Router", "IOS", None),
            r"\.9\.1\.(1577|1578|1579|1580)$": ("Router", "IOS-XE", None),
            r"\.9\.1\.(669|670|671|672|673|674|675)$": ("Firewall", "ASA", None),
            r"\.9\.1\.(1194|1195|1196|1197|1198|1199)$": ("Firewall", "ASA", None),
            r"\.9\.12\.3\.1\.3\.": ("Switch", "NX-OS", None),
        }

        for pattern, (device_type, platform, model) in oid_patterns.items():
            if re.search(pattern, sys_object_id):
                result["device_type"] = device_type
                result["platform"] = platform
                result["model"] = model
                break

        return result

    def get_collection_oids(self) -> dict[str, str]:
        """Return OIDs to collect for Cisco devices."""
        return self.CISCO_OIDS.copy()

    def parse_collected_data(
        self, raw_data: dict[str, Any], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """Parse Cisco-specific SNMP responses."""
        parsed: dict[str, Any] = {}

        # Serial number: try entity MIB first, fall back to old chassis MIB
        ent_serial = raw_data.get("ent_serial", "")
        chassis_serial = raw_data.get("chassis_serial", "")

        # Use entity serial if it looks valid (not empty, not just whitespace)
        if ent_serial and ent_serial.strip():
            parsed["serial_number"] = ent_serial.strip()
        elif chassis_serial and chassis_serial.strip():
            parsed["serial_number"] = chassis_serial.strip()
        else:
            parsed["serial_number"] = None

        # Model name: try various Entity MIB locations for exact model
        # Index 1 is often empty on stacks, so check 1001/1000 (stack master)
        ent_model = raw_data.get("ent_model", "")
        ent_model_1001 = raw_data.get("ent_model_1001", "")
        ent_model_1000 = raw_data.get("ent_model_1000", "")
        ent_descr = raw_data.get("ent_descr", "")

        # Prefer exact model from stack master location
        if ent_model_1001 and ent_model_1001.strip():
            parsed["model"] = ent_model_1001.strip()
        elif ent_model_1000 and ent_model_1000.strip():
            parsed["model"] = ent_model_1000.strip()
        elif ent_model and ent_model.strip():
            parsed["model"] = ent_model.strip()
        elif ent_descr and ent_descr.strip():
            # Entity description often contains model info
            parsed["model"] = self._extract_model_from_ent_descr(ent_descr)
        elif sys_descr:
            # Fall back to parsing sysDescr
            model_info = self._parse_model_from_sysdescr(sys_descr)
            parsed["model"] = model_info.get("model")
        else:
            parsed["model"] = None

        # Software version: try entity MIB, then parse from sysDescr
        ent_sw_rev = raw_data.get("ent_sw_rev", "")

        if ent_sw_rev and ent_sw_rev.strip():
            parsed["software_version"] = ent_sw_rev.strip()
        elif sys_descr:
            parsed["software_version"] = self._extract_version_from_sysdescr(sys_descr)
        else:
            parsed["software_version"] = None

        return parsed

    def _extract_model_from_ent_descr(self, ent_descr: str) -> str | None:
        """Extract model from entity physical description."""
        if not ent_descr:
            return None

        # Common patterns in entPhysicalDescr
        patterns = [
            r"(C9\d{3}[A-Z0-9\-]*)",
            r"(WS-C\d{4}[A-Z0-9\-]*)",
            r"(N\d{1,2}K-C\d+[A-Z0-9\-]*)",
            r"Catalyst\s+(\d{4}[A-Z0-9\-]*)",
            r"(Nexus\s*\d{4}[A-Z0-9\-]*)",
        ]

        for pattern in patterns:
            match = re.search(pattern, ent_descr, re.I)
            if match:
                return match.group(1).strip()

        # If no pattern matches but it's a reasonable string, return as-is
        if len(ent_descr) < 50 and ent_descr.strip():
            return ent_descr.strip()

        return None

    def _extract_version_from_sysdescr(self, sys_descr: str) -> str | None:
        """Extract software version from sysDescr."""
        if not sys_descr:
            return None

        # Pattern for "Version X.X.X" or "Version X.X(X)X"
        version_patterns = [
            # IOS-XE style: "Version 17.03.03" - also handles "Codename 17.03.03"
            r"Version\s+(\d+\.\d+\.\d+[a-zA-Z0-9]*)",
            # IOS style: "Version 12.2(44)SE4" or "Version 15.2(4)M1"
            r"Version\s+(\d+\.\d+\(\d+\)[A-Z]+\d*)",
            # NX-OS style: "version 7.0(3)I7(6)"
            r"[Vv]ersion\s+(\d+\.\d+\(\d+\)[A-Z]*\d*\(\d+\))",
            # ASA style: "Version 9.8(2)"
            r"Version\s+(\d+\.\d+\(\d+\)\d*)",
            # Generic fallback
            r"Version\s+(\d+\.\d+[^\s,]*)",
        ]

        for pattern in version_patterns:
            match = re.search(pattern, sys_descr, re.I)
            if match:
                version = match.group(1)
                # Strip codename prefix if present (e.g., "Gibraltar 16.12.14" -> "16.12.14")
                # Codenames are single words before the version number
                version_match = re.search(r"(\d+\.\d+\.\d+[a-zA-Z0-9()]*)", version)
                if version_match:
                    return version_match.group(1)
                return version

        return None

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

        # First pass: collect all chassis/stack candidates
        chassis_candidates: list[EntityComponent] = []

        for comp in components.values():
            # Skip empty/placeholder entries
            if not comp.description and not comp.name and not comp.model_name:
                continue

            if comp.entity_class == 3:  # Chassis
                if inventory.chassis is None:
                    inventory.chassis = comp
                # Collect all chassis with model+serial as potential stack members
                if comp.model_name and comp.serial_number:
                    chassis_candidates.append(comp)
            elif comp.entity_class == 9:  # Module
                if comp.serial_number or comp.model_name:
                    inventory.modules.append(comp)
            elif comp.entity_class == 6:  # Power supply
                inventory.power_supplies.append(comp)
            elif comp.entity_class == 7:  # Fan
                inventory.fans.append(comp)
            elif comp.entity_class == 11:  # Stack (explicit stack entity)
                # Collect all stack entities with model+serial
                if comp.model_name and comp.serial_number:
                    chassis_candidates.append(comp)

        # Second pass: determine actual stack members
        # On Cisco stacks, index 1 is the stack container (e.g., "C9300-48P" but representing
        # the whole stack, not an individual switch). Actual switches are at 1000, 2000, 3000, etc.
        # We only want entries at index >= 1000 that have model + serial.
        for comp in chassis_candidates:
            # Only include high-index entries (1000+) as stack members
            # Index 1 is always the stack container, even if it has the same model
            if comp.index >= 1000 and comp.model_name and comp.serial_number:
                inventory.stack_members.append(comp)

        # Sort stack members by index (lower = stack master typically, 1000 before 2000)
        inventory.stack_members.sort(key=lambda x: x.index)

        # Sort modules by position
        inventory.modules.sort(key=lambda x: (x.contained_in or 0, x.parent_rel_pos or 0))

        return inventory

    def parse_basic_info_from_entity_walk(
        self, walk_results: dict[str, list[tuple[str, str]]], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """
        Cisco-specific override to handle stack switch indexing.

        On Cisco stacks, index 1 is often a "stack container" (e.g., "c36xx Stack")
        that has the same serial as the stack master but no specific model.
        The actual switches are at indices 1000, 1001, 2000, 2001, etc.

        We prefer indices >= 1000 for chassis/stack entities to get the actual
        switch model and serial, not the stack container.
        """
        result: dict[str, Any] = {
            "serial_number": None,
            "model": None,
            "software_version": None,
        }

        # Build a map of index -> data from walk results
        entities: dict[int, dict[str, Any]] = {}

        def get_index(oid: str, base_oid: str) -> int | None:
            """Extract entity index from full OID."""
            suffix = oid.replace(base_oid + ".", "")
            try:
                return int(suffix.split(".")[0])
            except (ValueError, IndexError):
                return None

        # Parse entity classes first to identify chassis/stack members
        class_results = walk_results.get("entPhysicalClass", [])
        for full_oid, value in class_results:
            idx = get_index(full_oid, ENTITY_MIB_OIDS["entPhysicalClass"])
            if idx is not None:
                try:
                    entities[idx] = {"class": int(value)}
                except ValueError:
                    pass

        # Parse serial numbers
        serial_results = walk_results.get("entPhysicalSerialNum", [])
        for full_oid, value in serial_results:
            idx = get_index(full_oid, ENTITY_MIB_OIDS["entPhysicalSerialNum"])
            if idx is not None and value and value.strip():
                if idx not in entities:
                    entities[idx] = {}
                entities[idx]["serial"] = value.strip()

        # Parse model names
        model_results = walk_results.get("entPhysicalModelName", [])
        for full_oid, value in model_results:
            idx = get_index(full_oid, ENTITY_MIB_OIDS["entPhysicalModelName"])
            if idx is not None and value and value.strip():
                if idx not in entities:
                    entities[idx] = {}
                entities[idx]["model"] = value.strip()

        # Parse software revisions
        sw_results = walk_results.get("entPhysicalSoftwareRev", [])
        for full_oid, value in sw_results:
            idx = get_index(full_oid, ENTITY_MIB_OIDS["entPhysicalSoftwareRev"])
            if idx is not None and value and value.strip():
                if idx not in entities:
                    entities[idx] = {}
                entities[idx]["software_rev"] = value.strip()

        # Find chassis or stack components (class 3 or 11) with serial numbers
        # Separate into "high" indices (1000+, actual switches) and "low" indices (stack containers)
        high_index_candidates = []
        low_index_candidates = []

        for idx, data in entities.items():
            entity_class = data.get("class", 0)
            if entity_class in (ENTITY_CLASS_CHASSIS, ENTITY_CLASS_STACK):
                if data.get("serial"):
                    if idx >= 1000:
                        high_index_candidates.append((idx, data))
                    else:
                        low_index_candidates.append((idx, data))

        # Prefer high-index entries (actual switches) over low-index (stack containers)
        # Sort by index to get stack master (lowest in range)
        high_index_candidates.sort(key=lambda x: x[0])
        low_index_candidates.sort(key=lambda x: x[0])

        if high_index_candidates:
            # Use first high-index chassis/stack with a serial number (stack master)
            _, chassis_data = high_index_candidates[0]
            result["serial_number"] = chassis_data.get("serial")
            result["model"] = chassis_data.get("model")
            result["software_version"] = chassis_data.get("software_rev")
        elif low_index_candidates:
            # Fall back to low-index if no high-index found
            _, chassis_data = low_index_candidates[0]
            result["serial_number"] = chassis_data.get("serial")
            result["model"] = chassis_data.get("model")
            result["software_version"] = chassis_data.get("software_rev")
        else:
            # Fallback: find any entity with serial number (preferring high indices)
            serial_candidates = [
                (idx, data) for idx, data in entities.items() if data.get("serial")
            ]
            # Sort preferring high indices first, then by index within range
            serial_candidates.sort(key=lambda x: (0 if x[0] >= 1000 else 1, x[0]))

            if serial_candidates:
                _, fallback_data = serial_candidates[0]
                result["serial_number"] = fallback_data.get("serial")
                result["model"] = fallback_data.get("model")
                result["software_version"] = fallback_data.get("software_rev")

        # Clean up software version - strip codename if present (e.g., "Gibraltar 16.12.14" -> "16.12.14")
        if result["software_version"]:
            result["software_version"] = self._clean_version_string(result["software_version"])

        # Fallback: if no software version from Entity MIB, parse from sysDescr
        # This is common for ISR/ASR routers which don't populate entPhysicalSoftwareRev
        if not result["software_version"] and sys_descr:
            result["software_version"] = self._extract_version_from_sysdescr(sys_descr)

        return result

    def _clean_version_string(self, version: str) -> str:
        """
        Clean up version string by removing codenames.
        E.g., "Gibraltar 16.12.14" -> "16.12.14"
             "Denali 16.3.5" -> "16.3.5"
        """
        if not version:
            return version

        # If version starts with a letter, it likely has a codename prefix
        # Extract just the numeric version
        version_match = re.search(r"(\d+\.\d+[\.\d()A-Za-z]*)", version)
        if version_match:
            return version_match.group(1)
        return version

    def get_entity_mib_oids(self) -> dict[str, str]:
        """Return Entity MIB OID bases for walking."""
        return self.ENTITY_MIB_OIDS.copy()

    def get_license_mib_oids(self) -> dict[str, str]:
        """Return License MIB OID bases for walking."""
        return self.LICENSE_MIB_OIDS.copy()

    def parse_license_table(
        self, walk_results: dict[str, list[tuple[str, str]]]
    ) -> list[License]:
        """
        Parse CISCO-LICENSE-MGMT-MIB walk results into License objects.

        The table is indexed by: entPhysicalIndex.clmgmtLicenseStoreIndex.clmgmtLicenseIndex
        We use the full index as a unique identifier.

        Args:
            walk_results: Dict mapping OID name to list of (full_oid, value) tuples

        Returns:
            List of License objects
        """
        licenses: dict[str, License] = {}

        # Helper to extract composite index from OID
        def get_license_index(oid: str, base_oid: str) -> str | None:
            suffix = oid.replace(base_oid + ".", "")
            # Index format: entPhysicalIndex.storeIndex.licenseIndex
            parts = suffix.split(".")
            if len(parts) >= 3:
                return ".".join(parts[:3])  # Use all 3 parts as unique key
            return None

        # Parse each OID type
        for oid_name, results in walk_results.items():
            base_oid = self.LICENSE_MIB_OIDS.get(oid_name)
            if not base_oid:
                continue

            for full_oid, value in results:
                idx = get_license_index(full_oid, base_oid)
                if idx is None:
                    continue

                if idx not in licenses:
                    # Use hash of index for integer id
                    licenses[idx] = License(index=hash(idx) % 10000)

                lic = licenses[idx]
                value_str = str(value).strip() if value else None

                if oid_name == "clmgmtLicenseFeatureName":
                    lic.feature_name = value_str
                elif oid_name == "clmgmtLicenseType":
                    try:
                        lic.license_type = int(value_str) if value_str else None
                    except ValueError:
                        pass
                elif oid_name == "clmgmtLicenseEndDate":
                    # DateAndTime format - convert to readable string
                    lic.end_date = self._parse_date_and_time(value)
                elif oid_name == "clmgmtLicenseValidityPeriodRemaining":
                    try:
                        lic.validity_period_remaining = int(value_str) if value_str else None
                    except ValueError:
                        pass
                elif oid_name == "clmgmtLicenseMaxUsageCount":
                    try:
                        lic.max_count = int(value_str) if value_str else None
                    except ValueError:
                        pass
                elif oid_name == "clmgmtLicenseUsageCountRemaining":
                    try:
                        lic.count_remaining = int(value_str) if value_str else None
                    except ValueError:
                        pass
                elif oid_name == "clmgmtLicenseStatus":
                    try:
                        lic.status = int(value_str) if value_str else None
                    except ValueError:
                        pass

        # Filter out licenses without feature names (invalid entries)
        valid_licenses = [lic for lic in licenses.values() if lic.feature_name]

        # Sort by feature name for consistent display
        valid_licenses.sort(key=lambda x: x.feature_name or "")

        return valid_licenses

    def _parse_date_and_time(self, value: Any) -> str | None:
        """
        Parse SNMP DateAndTime (RFC 2579) to readable string.

        DateAndTime format: 8 or 11 octets
        - Octets 1-2: year (network byte order)
        - Octet 3: month (1-12)
        - Octet 4: day (1-31)
        - Octet 5: hour (0-23)
        - Octet 6: minute (0-59)
        - Octet 7: seconds (0-60)
        - Octet 8: deci-seconds (0-9)
        - Octets 9-11: timezone (optional)
        """
        if value is None:
            return None

        try:
            # Handle bytes or string representation
            if isinstance(value, bytes):
                data = value
            elif isinstance(value, str):
                # Try to decode hex string or use as bytes
                if all(c in "0123456789abcdefABCDEF" for c in value.replace(" ", "")):
                    data = bytes.fromhex(value.replace(" ", ""))
                else:
                    data = value.encode("latin-1")
            else:
                return str(value)

            if len(data) < 8:
                return str(value)

            year = (data[0] << 8) + data[1]
            month = data[2]
            day = data[3]
            hour = data[4]
            minute = data[5]
            second = data[6]

            # Validate ranges
            if not (1 <= month <= 12 and 1 <= day <= 31):
                return str(value)

            # Check for "no expiry" indicators (year 0 or very far future)
            if year == 0:
                return "Never"
            if year > 2100:
                return "Never"

            return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"

        except Exception:
            return str(value) if value else None
