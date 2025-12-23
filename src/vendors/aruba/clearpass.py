"""
Aruba ClearPass Policy Manager SNMP handling.

ClearPass uses CPPM-MIB for system information.
sysObjectID format: 1.3.6.1.4.1.14823.1.6.* (ClearPass products)

References:
- Aruba Enterprise OID: 14823
- CPPM-MIB: ClearPass system info (serial, model, version, hostname)
- sysObjectID: 1.3.6.1.4.1.14823.1.6 for ClearPass
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

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "index": self.index,
            "name": self.name,
            "description": self.description,
            "model": self.model_name,
            "serial": self.serial_number,
        }


@dataclass
class DeviceInventory:
    """Device inventory for ClearPass appliances."""

    chassis: EntityComponent | None = None
    all_components: list[EntityComponent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "chassis": self.chassis.to_dict() if self.chassis else None,
        }


class ClearPassHandler(VendorHandler):
    """Handler for Aruba ClearPass Policy Manager appliances."""

    ENTERPRISE_ID = 14823
    OID_PREFIX = "1.3.6.1.4.1.14823"

    # CPPM-MIB OIDs for ClearPass system information
    # Base: 1.3.6.1.4.1.14823.1.6.1.1.1.1.1
    # Note: Index is .0 for scalar values
    CLEARPASS_OIDS = {
        # cppmSystemModel
        "model": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.1.0",
        # cppmSystemSerialNumber
        "serial_number": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.2.0",
        # cppmSystemVersion
        "sw_version": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.3.0",
        # cppmSystemHostname
        "hostname": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.4.0",
        # cppmClusterNodeType (1=publisher, 2=subscriber)
        "cluster_node_type": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.5.0",
        # cppmZoneName
        "zone_name": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.6.0",
        # cppmNumClusterNodes
        "cluster_nodes": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.7.0",
        # cppmNwMgmtPortIPAddress
        "mgmt_ip": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.8.0",
        # cppmSystemMemoryTotal
        "memory_total": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.12.0",
        # cppmSystemMemoryFree
        "memory_free": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.13.0",
        # cppmSystemDiskSpaceTotal
        "disk_total": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.14.0",
        # cppmSystemDiskSpaceFree
        "disk_free": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.15.0",
        # cppmSystemNumCPUs
        "num_cpus": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.16.0",
        # cppmSystemUptime
        "uptime": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.17.0",
        # cppmHardwareFanStatus
        "fan_status": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.19.0",
        # cppmHardwarePowerStatus
        "power_status": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.20.0",
        # cppmHardwareDiskStatus
        "disk_status": "1.3.6.1.4.1.14823.1.6.1.1.1.1.1.22.0",
        # Entity MIB fallbacks
        "ent_serial": "1.3.6.1.2.1.47.1.1.1.1.11.1",
        "ent_model": "1.3.6.1.2.1.47.1.1.1.1.13.1",
        "ent_descr": "1.3.6.1.2.1.47.1.1.1.1.2.1",
    }

    # Entity MIB OID bases for walking (standard MIB)
    ENTITY_MIB_OIDS = {
        "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2",
        "entPhysicalClass": "1.3.6.1.2.1.47.1.1.1.1.5",
        "entPhysicalName": "1.3.6.1.2.1.47.1.1.1.1.7",
        "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11",
        "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13",
    }

    # ClearPass model mapping
    MODEL_MAP = {
        "CP-HW-500": "ClearPass 500",
        "CP-HW-5K": "ClearPass 5K",
        "CP-HW-25K": "ClearPass 25K",
        "CP-VA-500": "ClearPass VM 500",
        "CP-VA-5K": "ClearPass VM 5K",
        "CP-VA-25K": "ClearPass VM 25K",
        "YOURDEVICEMODEL": "ClearPass",  # Generic fallback
    }

    @property
    def vendor_name(self) -> str:
        return "aruba"

    @property
    def enterprise_id(self) -> int:
        return self.ENTERPRISE_ID

    def matches_sys_object_id(self, sys_object_id: str) -> bool:
        """
        Check if sysObjectID belongs to ClearPass.

        ClearPass uses: 1.3.6.1.4.1.14823.1.6.*
        Also check for older ClearPass using net-snmp OID with Aruba description.
        """
        normalized = sys_object_id.lstrip(".")
        # ClearPass specific OID path
        return normalized.startswith("1.3.6.1.4.1.14823.1.6")

    def identify_device_type(
        self, sys_object_id: str, sys_descr: str | None
    ) -> dict[str, str | None]:
        """Identify ClearPass device type."""
        result: dict[str, str | None] = {
            "device_type": "Policy Manager",
            "platform": "ClearPass",
            "model": "ClearPass Policy Manager",  # Default model name
        }

        # Try to extract more specific model from sysDescr
        if sys_descr:
            model_info = self._parse_model_from_sysdescr(sys_descr)
            if model_info.get("model"):
                result["model"] = model_info["model"]

        return result

    def _parse_model_from_sysdescr(self, sys_descr: str) -> dict[str, str | None]:
        """
        Extract model from sysDescr.

        ClearPass sysDescr examples:
        - "ClearPass Policy Manager"
        - "Aruba ClearPass Policy Manager Virtual Appliance"
        - "Linux clearpass 4.14.0-1-amd64..."
        - "...Model: C2000 (R220)..."
        - "...Model: C3000..."
        """
        result: dict[str, str | None] = {
            "model": None,
        }

        sys_descr_lower = sys_descr.lower()

        # Try to extract specific model patterns first
        model_patterns = [
            # "Model: C2000 (R220)" or "Model: C3000" - extract just C2000/C3000/etc
            (r"Model:\s*(C\d+)", "ClearPass {}"),
            (r"(CP-HW-\w+)", None),
            (r"(CP-VA-\w+)", None),
            (r"ClearPass\s+(\d+[K]?)", "ClearPass {}"),
        ]

        for pattern, fmt in model_patterns:
            match = re.search(pattern, sys_descr, re.I)
            if match:
                model = match.group(1).upper()
                if model in self.MODEL_MAP:
                    result["model"] = self.MODEL_MAP[model]
                elif fmt:
                    result["model"] = fmt.format(model)
                else:
                    result["model"] = model
                return result

        # Fall back to generic detection
        if "clearpass" in sys_descr_lower:
            if "virtual" in sys_descr_lower or "linux" in sys_descr_lower:
                result["model"] = "ClearPass Policy Manager VM"
            else:
                result["model"] = "ClearPass Policy Manager"

        return result

    def get_collection_oids(self) -> dict[str, str]:
        """Return OIDs to collect for ClearPass."""
        return self.CLEARPASS_OIDS.copy()

    def parse_collected_data(
        self, raw_data: dict[str, Any], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """Parse ClearPass-specific SNMP responses."""
        parsed: dict[str, Any] = {}

        # Serial number: prefer CPPM-MIB, fallback to Entity MIB
        serial = raw_data.get("serial_number", "")
        ent_serial = raw_data.get("ent_serial", "")

        if serial and serial.strip():
            parsed["serial_number"] = serial.strip()
        elif ent_serial and ent_serial.strip():
            parsed["serial_number"] = ent_serial.strip()
        else:
            parsed["serial_number"] = None

        # Model: prefer CPPM-MIB, fallback to Entity MIB or sysDescr
        model = raw_data.get("model", "")
        ent_model = raw_data.get("ent_model", "")

        if model and model.strip():
            model_str = model.strip()
            # Map model string to friendly name
            parsed["model"] = self.MODEL_MAP.get(model_str, model_str)
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

        # Additional ClearPass-specific metadata
        parsed["metadata"] = {}

        # Cluster info
        cluster_type = raw_data.get("cluster_node_type", "")
        if cluster_type:
            type_map = {"1": "publisher", "2": "subscriber"}
            parsed["metadata"]["cluster_node_type"] = type_map.get(
                str(cluster_type).strip(), cluster_type
            )

        if raw_data.get("zone_name"):
            parsed["metadata"]["zone_name"] = raw_data["zone_name"].strip()
        if raw_data.get("cluster_nodes"):
            try:
                parsed["metadata"]["cluster_nodes"] = int(raw_data["cluster_nodes"])
            except ValueError:
                pass

        # Resource info
        if raw_data.get("num_cpus"):
            try:
                parsed["metadata"]["num_cpus"] = int(raw_data["num_cpus"])
            except ValueError:
                pass

        # Hardware status
        status_map = {"1": "ok", "2": "warning", "3": "critical"}
        if raw_data.get("fan_status"):
            parsed["metadata"]["fan_status"] = status_map.get(
                str(raw_data["fan_status"]).strip(), raw_data["fan_status"]
            )
        if raw_data.get("power_status"):
            parsed["metadata"]["power_status"] = status_map.get(
                str(raw_data["power_status"]).strip(), raw_data["power_status"]
            )
        if raw_data.get("disk_status"):
            parsed["metadata"]["disk_status"] = status_map.get(
                str(raw_data["disk_status"]).strip(), raw_data["disk_status"]
            )

        # Clean up empty metadata
        if not parsed["metadata"]:
            del parsed["metadata"]

        return parsed

    def _extract_version_from_sysdescr(self, sys_descr: str) -> str | None:
        """Extract ClearPass version from sysDescr."""
        if not sys_descr:
            return None

        version_patterns = [
            r"Version\s+(\d+\.\d+\.\d+)",
            r"ClearPass\s+(\d+\.\d+\.\d+)",
            r"(\d+\.\d+\.\d+)",
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
            if comp.entity_class == 3:  # Chassis
                if inventory.chassis is None:
                    inventory.chassis = comp
                break

        return inventory

    def parse_basic_info_from_entity_walk(
        self, walk_results: dict[str, list[tuple[str, str]]], sys_descr: str | None = None
    ) -> dict[str, Any]:
        """ClearPass-specific override."""
        result = super().parse_basic_info_from_entity_walk(walk_results, sys_descr)

        if not result.get("software_version") and sys_descr:
            result["software_version"] = self._extract_version_from_sysdescr(sys_descr)

        return result
