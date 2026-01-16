"""
Nautobot sync service for orchestrating device synchronization.
"""
import logging
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network

from src.db.models import Device, NautobotSyncStatus
from src.integrations.nautobot.client import NautobotClient, PrefixInfo
from src.integrations.nautobot.mapper import (
    map_device_to_nautobot,
    map_device_type_to_role,
    sanitize_nautobot_name,
    get_device_name,
)

logger = logging.getLogger(__name__)


@dataclass
class LocationStatus:
    """Status of a device's location in Nautobot."""
    has_prefix: bool
    has_location: bool
    prefix_id: str | None = None
    prefix_cidr: str | None = None
    location_id: str | None = None
    location_name: str | None = None


@dataclass
class PrefixResult:
    """Result of ensuring a prefix exists."""
    success: bool
    prefix_id: str | None = None
    prefix_cidr: str | None = None
    ip_id: str | None = None
    created_prefix: bool = False
    created_ip: bool = False
    error: str | None = None


@dataclass
class SyncResult:
    """Result of syncing a single device."""
    success: bool
    device_id: str
    nautobot_device_id: str | None = None
    status: str = "pending"  # pending, no_prefix, no_location, ready, synced, failed
    error: str | None = None


@dataclass
class SyncSummary:
    """Summary of a batch sync operation."""
    total: int = 0
    synced: int = 0
    no_prefix: int = 0
    no_location: int = 0
    failed: int = 0
    errors: list[str] | None = None


class NautobotSyncService:
    """Service for syncing devices to Nautobot."""

    def __init__(self, client: NautobotClient):
        self.client = client

    def _is_stack_device(self, device: Device) -> bool:
        """Check if device is a stack with multiple members."""
        if not device.metadata_:
            return False
        inventory = device.metadata_.get("inventory", {})
        # It's a stack if is_stack flag is set or there are multiple stack members
        if inventory.get("is_stack"):
            return True
        stack_members = inventory.get("stack_members", [])
        return len(stack_members) > 1

    def _get_stack_members(self, device: Device) -> list[dict]:
        """Get stack members from device inventory."""
        if not device.metadata_:
            return []
        inventory = device.metadata_.get("inventory", {})
        return inventory.get("stack_members", [])

    def _is_wlc_device(self, device: Device) -> bool:
        """Check if device is a wireless controller with access points."""
        if not device.metadata_:
            return False
        inventory = device.metadata_.get("inventory", {})
        access_points = inventory.get("access_points", [])
        return len(access_points) > 0

    def _get_access_points(self, device: Device) -> list[dict]:
        """Get access points from device inventory."""
        if not device.metadata_:
            return []
        inventory = device.metadata_.get("inventory", {})
        return inventory.get("access_points", [])

    def check_device_location_status(self, device: Device) -> LocationStatus:
        """
        Check if a device can be synced to Nautobot.

        Queries Nautobot to find if the device's IP is in a prefix
        that has a location assigned.
        """
        ip_address = str(device.ip_address)

        try:
            prefix_info = self.client.get_prefix_for_ip(ip_address)

            if not prefix_info:
                return LocationStatus(
                    has_prefix=False,
                    has_location=False,
                )

            return LocationStatus(
                has_prefix=True,
                has_location=prefix_info.location_id is not None,
                prefix_id=prefix_info.id,
                prefix_cidr=prefix_info.prefix,
                location_id=prefix_info.location_id,
                location_name=prefix_info.location_name,
            )
        except Exception as e:
            logger.error(f"Failed to check location status for {ip_address}: {e}")
            raise

    def ensure_prefix_and_ip(self, device: Device) -> PrefixResult:
        """
        Ensure device's prefix and IP exist in Nautobot.
        Creates them if missing, tagged with Nova Inventory.

        Uses the device's management_subnet if available, otherwise
        creates a /24 based on the IP address.
        """
        ip_address = str(device.ip_address)

        try:
            # First check if prefix already exists
            existing_prefix = self.client.get_prefix_for_ip(ip_address)

            created_prefix = False
            prefix_id = None
            prefix_cidr = None

            if existing_prefix:
                prefix_id = existing_prefix.id
                prefix_cidr = existing_prefix.prefix
            else:
                # Need to create prefix
                if device.management_subnet:
                    prefix_cidr = device.management_subnet
                else:
                    # Default to /24 based on IP
                    ip = IPv4Address(ip_address)
                    network = IPv4Network(f"{ip}/24", strict=False)
                    prefix_cidr = str(network)

                # Create the prefix (no description - let user add in Nautobot if needed)
                new_prefix = self.client.create_prefix(prefix=prefix_cidr)
                prefix_id = new_prefix.id
                created_prefix = True

            # Ensure IP address exists
            ip_result = self.client.get_or_create_ip_address(ip_address, prefix_id)

            return PrefixResult(
                success=True,
                prefix_id=prefix_id,
                prefix_cidr=prefix_cidr,
                ip_id=ip_result["id"],
                created_prefix=created_prefix,
                created_ip=ip_result["created"],
            )
        except Exception as e:
            logger.error(f"Failed to ensure prefix/IP for {ip_address}: {e}")
            return PrefixResult(
                success=False,
                error=str(e),
            )

    def sync_device(self, device: Device) -> SyncResult:
        """
        Sync a device to Nautobot.

        This performs the full sync:
        1. Check if device IP has a prefix with location
        2. If no prefix, return no_prefix status
        3. If prefix but no location, return no_location status
        4. If location exists, create/update device in Nautobot
        5. For stack devices, create virtual chassis with all stack members
        """
        device_id = str(device.id)
        ip_address = str(device.ip_address)

        try:
            # Check location status
            location_status = self.check_device_location_status(device)

            if not location_status.has_prefix:
                return SyncResult(
                    success=False,
                    device_id=device_id,
                    status="no_prefix",
                    error="No prefix found in Nautobot for device IP",
                )

            if not location_status.has_location:
                return SyncResult(
                    success=False,
                    device_id=device_id,
                    status="no_location",
                    error=f"Prefix {location_status.prefix_cidr} has no location assigned",
                )

            # Check if this is a stack device
            if self._is_stack_device(device):
                return self._sync_stack_device(device, location_status)

            # Check if this is a wireless controller with access points
            if self._is_wlc_device(device):
                return self._sync_wlc_device(device, location_status)

            # Get device mapping for non-stack device
            device_data = map_device_to_nautobot(device, location_status.location_id)

            # Check if device already exists in Nautobot (by serial number)
            existing_device = self.client.get_device_by_serial(device_data["serial"])

            if existing_device:
                # Update existing device (name may have changed, status may have changed)
                self.client.update_device(
                    nautobot_id=existing_device["id"],
                    name=device_data["name"],
                    status="Active" if device.is_active else "Offline",
                    software_version=device_data.get("software_version"),
                    platform_name=device_data.get("platform"),
                )

                # Sync inventory items (components) if available
                if device.metadata_ and device.metadata_.get("inventory"):
                    manufacturer_id = self.client.get_or_create_manufacturer(device_data["manufacturer"])
                    self.client.sync_inventory_items(
                        device_id=existing_device["id"],
                        inventory_data=device.metadata_["inventory"],
                        manufacturer_id=manufacturer_id,
                    )

                return SyncResult(
                    success=True,
                    device_id=device_id,
                    nautobot_device_id=existing_device["id"],
                    status="synced",
                )

            # Serial not found - check if device exists by name (serial may have changed = hardware replacement)
            existing_by_name = self.client.get_device_by_name(device_data["name"])
            if existing_by_name:
                # Rename old device to preserve inventory history (hardware replacement scenario)
                from datetime import datetime
                decom_date = datetime.now().strftime("%Y-%m-%d")
                decom_name = f"DECOM-{device_data['name']}-{decom_date}"
                self.client.update_device(
                    nautobot_id=existing_by_name["id"],
                    name=decom_name,
                    status="Offline",
                )
                logger.info(f"Renamed old device to {decom_name} (hardware replacement)")
                # Fall through to create new device with original name

            # Create device in Nautobot
            # First ensure we have manufacturer, device type, and role
            manufacturer_id = self.client.get_or_create_manufacturer(device_data["manufacturer"])
            device_type_id = self.client.get_or_create_device_type(
                manufacturer_id, device_data["model"]
            )
            role_id = self.client.get_or_create_role(device_data["role"])

            # Ensure IP exists
            ip_result = self.client.get_or_create_ip_address(ip_address)

            # Create device
            nautobot_device_id = self.client.create_device(
                name=device_data["name"],
                device_type_id=device_type_id,
                role_id=role_id,
                location_id=location_status.location_id,
                serial=device_data["serial"],
                primary_ip_id=ip_result["id"],
                software_version=device_data.get("software_version"),
                platform_name=device_data.get("platform"),
            )

            # Sync inventory items (components) if available
            if device.metadata_ and device.metadata_.get("inventory"):
                self.client.sync_inventory_items(
                    device_id=nautobot_device_id,
                    inventory_data=device.metadata_["inventory"],
                    manufacturer_id=manufacturer_id,
                )

            return SyncResult(
                success=True,
                device_id=device_id,
                nautobot_device_id=nautobot_device_id,
                status="synced",
            )

        except Exception as e:
            logger.error(f"Failed to sync device {ip_address}: {e}")
            return SyncResult(
                success=False,
                device_id=device_id,
                status="failed",
                error=str(e),
            )

    def _sync_stack_device(self, device: Device, location_status: LocationStatus) -> SyncResult:
        """
        Sync a stack device to Nautobot.

        Creates:
        1. Individual devices for each stack member
        2. A virtual chassis linking all stack members
        3. Inventory items assigned to their respective stack member devices
        """
        device_id = str(device.id)
        ip_address = str(device.ip_address)
        base_name = get_device_name(device)
        inventory = device.metadata_.get("inventory", {})
        stack_members = self._get_stack_members(device)

        logger.info(f"Syncing stack device {base_name} with {len(stack_members)} members")

        try:
            # Get manufacturer and role
            manufacturer_name = sanitize_nautobot_name(device.vendor)
            manufacturer_id = self.client.get_or_create_manufacturer(manufacturer_name)
            role_id = self.client.get_or_create_role(map_device_type_to_role(device.device_type))

            # Ensure IP exists for the master
            ip_result = self.client.get_or_create_ip_address(ip_address)

            # Create devices for each stack member
            member_devices = {}  # index -> nautobot_device_id
            master_device_id = None

            for member in stack_members:
                member_index = member.get("index", 0)
                switch_num = member_index // 1000 if member_index >= 1000 else member_index
                member_model = member.get("model") or device.model
                member_serial = member.get("serial")
                member_name = f"{base_name}-{switch_num}"
                # Get software version from stack member data or fall back to device software version
                member_sw_version = member.get("software_version") or device.software_version

                # Get or create device type for this member's model
                device_type_id = self.client.get_or_create_device_type(
                    manufacturer_id, sanitize_nautobot_name(member_model)
                )

                # Check if this stack member device already exists (by serial number)
                existing_member = self.client.get_device_by_serial(member_serial)

                if existing_member:
                    member_device_id = existing_member["id"]
                    # Update name, status, and software version
                    self.client.update_device(
                        nautobot_id=member_device_id,
                        name=member_name,
                        status="Active" if device.is_active else "Offline",
                        software_version=member_sw_version,
                        platform_name=device.platform,
                    )
                else:
                    # Serial not found - check if device exists by name (serial may have changed = hardware replacement)
                    existing_by_name = self.client.get_device_by_name(member_name)
                    if existing_by_name:
                        # Remove from virtual chassis before renaming (frees up the vc_position)
                        self.client.remove_device_from_virtual_chassis(existing_by_name["id"])

                        # Rename old device to preserve inventory history (hardware replacement scenario)
                        from datetime import datetime
                        decom_date = datetime.now().strftime("%Y-%m-%d")
                        decom_name = f"DECOM-{member_name}-{decom_date}"
                        self.client.update_device(
                            nautobot_id=existing_by_name["id"],
                            name=decom_name,
                            status="Offline",
                        )
                        logger.info(f"Renamed old device to {decom_name} (hardware replacement)")

                    # Create the stack member device (whether old device existed or not)
                    member_device_id = self.client.create_stack_device(
                        name=member_name,
                        device_type_id=device_type_id,
                        role_id=role_id,
                        location_id=location_status.location_id,
                        serial=member_serial,
                        software_version=member_sw_version,
                        platform_name=device.platform,
                    )

                member_devices[member_index] = member_device_id

                # First member (lowest index) is the master and gets the primary IP
                if master_device_id is None:
                    master_device_id = member_device_id
                    # Assign primary IP to master device
                    self.client.update_device(
                        nautobot_id=master_device_id,
                        primary_ip_id=ip_result["id"],
                    )

            # Create or get virtual chassis
            vc_name = base_name
            vc_id = self.client.get_or_create_virtual_chassis(vc_name, master_device_id)

            # Add all devices to the virtual chassis
            for member in stack_members:
                member_index = member.get("index", 0)
                switch_num = member_index // 1000 if member_index >= 1000 else member_index
                member_device_id = member_devices.get(member_index)

                if member_device_id:
                    # Determine priority (higher for master/standby)
                    role = member.get("role", "").lower()
                    if role == "active" or role == "master":
                        priority = 255
                    elif role == "standby":
                        priority = 200
                    else:
                        priority = member.get("priority", 100)

                    self.client.add_device_to_virtual_chassis(
                        device_id=member_device_id,
                        virtual_chassis_id=vc_id,
                        vc_position=switch_num,
                        vc_priority=priority,
                    )

            # Set master on virtual chassis
            if master_device_id:
                self.client.set_virtual_chassis_master(vc_id, master_device_id)

            # Sync inventory items to appropriate stack member devices
            self._sync_stack_inventory_items(
                inventory=inventory,
                member_devices=member_devices,
                manufacturer_id=manufacturer_id,
            )

            logger.info(f"Successfully synced stack {base_name} with {len(member_devices)} members")

            return SyncResult(
                success=True,
                device_id=device_id,
                nautobot_device_id=master_device_id,
                status="synced",
            )

        except Exception as e:
            logger.error(f"Failed to sync stack device {ip_address}: {e}")
            return SyncResult(
                success=False,
                device_id=device_id,
                status="failed",
                error=str(e),
            )

    def _sync_stack_inventory_items(
        self,
        inventory: dict,
        member_devices: dict[int, str],
        manufacturer_id: str,
    ) -> None:
        """
        Sync inventory items to their respective stack member devices.

        Uses the contained_in field to determine which stack member
        each item belongs to.
        """
        # Build a mapping from index ranges to device IDs
        # Stack members have indices like 1000, 2000, 3000...
        # Components have contained_in pointing to those indices

        def get_device_for_index(contained_in: int) -> str | None:
            """Find the device ID for a given contained_in index."""
            if not contained_in:
                return None

            # Direct match
            if contained_in in member_devices:
                return member_devices[contained_in]

            # Find the nearest stack member (floor division to get stack index)
            # E.g., contained_in=1500 should map to index 1000
            stack_index = (contained_in // 1000) * 1000
            return member_devices.get(stack_index)

        # Group components by their target device
        components_by_device: dict[str, list[dict]] = {}

        # Process modules
        for module in inventory.get("modules", []):
            if module.get("serial") and not module.get("removed_at"):
                contained_in = module.get("contained_in", 0)
                device_id = get_device_for_index(contained_in)
                if device_id:
                    if device_id not in components_by_device:
                        components_by_device[device_id] = []
                    components_by_device[device_id].append({
                        "name": module.get("name") or module.get("description") or "Module",
                        "part_id": module.get("model") or "",
                        "serial": module.get("serial"),
                    })

        # Process power supplies
        for psu in inventory.get("power_supplies", []):
            if psu.get("serial") and not psu.get("removed_at"):
                contained_in = psu.get("contained_in", 0)
                device_id = get_device_for_index(contained_in)
                if device_id:
                    if device_id not in components_by_device:
                        components_by_device[device_id] = []
                    components_by_device[device_id].append({
                        "name": psu.get("name") or psu.get("description") or "Power Supply",
                        "part_id": psu.get("model") or "",
                        "serial": psu.get("serial"),
                    })

        # Process fans
        for fan in inventory.get("fans", []):
            if fan.get("serial") and not fan.get("removed_at"):
                contained_in = fan.get("contained_in", 0)
                device_id = get_device_for_index(contained_in)
                if device_id:
                    if device_id not in components_by_device:
                        components_by_device[device_id] = []
                    components_by_device[device_id].append({
                        "name": fan.get("name") or fan.get("description") or "Fan",
                        "part_id": fan.get("model") or "",
                        "serial": fan.get("serial"),
                    })

        # Create/update inventory items for each device and mark removed ones
        tag_id = self.client.get_or_create_tag()
        from datetime import datetime
        removed_timestamp = datetime.now().strftime("%Y-%m-%d")

        for device_id, components in components_by_device.items():
            # Get existing inventory items for this device
            existing_items = {
                item.serial: item
                for item in self.client.api.dcim.inventory_items.filter(device=device_id)
                if item.serial
            }

            # Track which serials we've seen
            seen_serials = set()

            for component in components:
                serial = component["serial"]
                seen_serials.add(serial)

                if serial not in existing_items:
                    try:
                        self.client.api.dcim.inventory_items.create(
                            device=device_id,
                            name=component["name"],
                            part_id=component["part_id"],
                            serial=serial,
                            manufacturer=manufacturer_id,
                            tags=[tag_id],
                        )
                    except Exception:
                        # Try without tags
                        try:
                            self.client.api.dcim.inventory_items.create(
                                device=device_id,
                                name=component["name"],
                                part_id=component["part_id"],
                                serial=serial,
                                manufacturer=manufacturer_id,
                            )
                        except Exception as e:
                            logger.warning(f"Failed to create inventory item {component['name']}: {e}")

            # Mark removed inventory items in description field
            for serial, item in existing_items.items():
                if serial not in seen_serials:
                    # Only mark items we created (tagged with our tag)
                    item_tags = [str(t) if hasattr(t, 'id') else str(t) for t in (item.tags or [])]
                    if tag_id in item_tags:
                        try:
                            current_desc = item.description or ""
                            if not current_desc.startswith("REMOVED:"):
                                item.description = f"REMOVED: {removed_timestamp}"
                                item.save()
                                logger.info(f"Marked inventory item {serial} as removed")
                        except Exception as e:
                            logger.warning(f"Failed to mark item {serial} as removed: {e}")

    def _sync_wlc_device(self, device: Device, location_status: LocationStatus) -> SyncResult:
        """
        Sync a wireless controller and its access points to Nautobot.

        Creates:
        1. The WLC device itself (if not already exists)
        2. Individual devices for each access point registered to the controller
        """
        device_id = str(device.id)
        ip_address = str(device.ip_address)
        access_points = self._get_access_points(device)

        logger.info(f"Syncing WLC {device.hostname or ip_address} with {len(access_points)} access points")

        try:
            # First sync the WLC itself as a normal device
            device_data = map_device_to_nautobot(device, location_status.location_id)

            # Get manufacturer and role for WLC
            manufacturer_id = self.client.get_or_create_manufacturer(device_data["manufacturer"])
            wlc_device_type_id = self.client.get_or_create_device_type(
                manufacturer_id, device_data["model"]
            )
            wlc_role_id = self.client.get_or_create_role(device_data["role"])

            # Ensure IP exists for the WLC
            ip_result = self.client.get_or_create_ip_address(ip_address)

            # Check if WLC already exists
            existing_wlc = self.client.get_device_by_serial(device_data["serial"])

            if existing_wlc:
                wlc_nautobot_id = existing_wlc["id"]
                self.client.update_device(
                    nautobot_id=wlc_nautobot_id,
                    name=device_data["name"],
                    status="Active" if device.is_active else "Offline",
                    software_version=device_data.get("software_version"),
                    platform_name=device_data.get("platform"),
                )
            else:
                wlc_nautobot_id = self.client.create_device(
                    name=device_data["name"],
                    device_type_id=wlc_device_type_id,
                    role_id=wlc_role_id,
                    location_id=location_status.location_id,
                    serial=device_data["serial"],
                    primary_ip_id=ip_result["id"],
                    software_version=device_data.get("software_version"),
                    platform_name=device_data.get("platform"),
                )

            # Get or create AP role
            ap_role_id = self.client.get_or_create_role("Access Point")

            # Sync each access point as a device
            ap_count = 0
            for ap in access_points:
                ap_serial = ap.get("serial_number")
                ap_name = ap.get("name")
                ap_model = ap.get("model")
                ap_ip = ap.get("ip_address")
                ap_status = ap.get("status", "").lower()
                ap_software_version = ap.get("software_version")
                # Use AP platform if available, or derive from WLC vendor
                ap_platform = ap.get("platform") or f"{device.vendor} AP" if device.vendor else None

                # Skip APs without serial numbers (can't uniquely identify them)
                if not ap_serial:
                    logger.warning(f"Skipping AP {ap_name} - no serial number")
                    continue

                # Use AP name, or generate one from serial if missing
                if not ap_name:
                    ap_name = f"AP-{ap_serial}"

                # Sanitize the AP name for Nautobot
                ap_name = sanitize_nautobot_name(ap_name)

                # Get or create device type for this AP model
                ap_device_type_id = self.client.get_or_create_device_type(
                    manufacturer_id,
                    sanitize_nautobot_name(ap_model) if ap_model else "Unknown-AP"
                )

                # Check if AP already exists in Nautobot (by serial)
                existing_ap = self.client.get_device_by_serial(ap_serial)

                # Determine AP status for Nautobot
                nautobot_status = "Active" if ap_status == "up" else "Offline"

                # Get or create AP IP if it has one
                ap_ip_id = None
                if ap_ip:
                    try:
                        ap_ip_result = self.client.get_or_create_ip_address(ap_ip)
                        ap_ip_id = ap_ip_result["id"]
                    except Exception as e:
                        logger.warning(f"Failed to create IP for AP {ap_name}: {e}")

                if existing_ap:
                    # Update existing AP
                    self.client.update_device(
                        nautobot_id=existing_ap["id"],
                        name=ap_name,
                        status=nautobot_status,
                        primary_ip_id=ap_ip_id,
                        software_version=ap_software_version,
                        platform_name=ap_platform,
                    )
                else:
                    # Check if device exists by name (serial may have changed = hardware replacement)
                    existing_by_name = self.client.get_device_by_name(ap_name)
                    if existing_by_name:
                        # Rename old AP to preserve history
                        decom_date = datetime.now().strftime("%Y-%m-%d")
                        decom_name = f"DECOM-{ap_name}-{decom_date}"
                        self.client.update_device(
                            nautobot_id=existing_by_name["id"],
                            name=decom_name,
                            status="Offline",
                        )
                        logger.info(f"Renamed old AP to {decom_name} (hardware replacement)")

                    # Create the AP device
                    self.client.create_device(
                        name=ap_name,
                        device_type_id=ap_device_type_id,
                        role_id=ap_role_id,
                        location_id=location_status.location_id,
                        serial=ap_serial,
                        primary_ip_id=ap_ip_id,
                        software_version=ap_software_version,
                        platform_name=ap_platform,
                    )

                ap_count += 1

            logger.info(f"Successfully synced WLC with {ap_count} access points")

            return SyncResult(
                success=True,
                device_id=device_id,
                nautobot_device_id=wlc_nautobot_id,
                status="synced",
            )

        except Exception as e:
            logger.error(f"Failed to sync WLC device {ip_address}: {e}")
            return SyncResult(
                success=False,
                device_id=device_id,
                status="failed",
                error=str(e),
            )

    def sync_devices(
        self,
        devices: list[Device],
        progress_callback: callable | None = None,
    ) -> SyncSummary:
        """
        Sync multiple devices to Nautobot.

        Args:
            devices: List of devices to sync
            progress_callback: Optional callback(current, total) for progress updates
        """
        summary = SyncSummary(total=len(devices), errors=[])

        for i, device in enumerate(devices):
            result = self.sync_device(device)

            if result.status == "synced":
                summary.synced += 1
            elif result.status == "no_prefix":
                summary.no_prefix += 1
            elif result.status == "no_location":
                summary.no_location += 1
            else:
                summary.failed += 1
                if result.error:
                    summary.errors.append(f"{device.ip_address}: {result.error}")

            if progress_callback:
                progress_callback(i + 1, len(devices))

        return summary

    def get_sync_status_summary(self, devices: list[Device]) -> dict:
        """
        Get a summary of sync status for multiple devices.

        Returns counts of devices in each status.
        """
        summary = {
            "total": len(devices),
            "no_prefix": 0,
            "no_location": 0,
            "ready": 0,
            "synced": 0,
            "pending": 0,
        }

        for device in devices:
            if device.nautobot_sync:
                status = device.nautobot_sync.sync_status
                if status in summary:
                    summary[status] += 1
                else:
                    summary["pending"] += 1
            else:
                summary["pending"] += 1

        return summary
