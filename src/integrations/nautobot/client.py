"""
Nautobot API client using pynautobot.
"""
import logging
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network

import pynautobot

from src.config.settings import get_settings

logger = logging.getLogger(__name__)


@dataclass
class PrefixInfo:
    """Information about a Nautobot prefix."""
    id: str
    prefix: str
    location_id: str | None
    location_name: str | None


@dataclass
class LocationInfo:
    """Information about a Nautobot location."""
    id: str
    name: str
    parent_id: str | None
    parent_name: str | None


class NautobotClient:
    """Client for interacting with Nautobot API."""

    def __init__(
        self,
        url: str | None = None,
        token: str | None = None,
        verify_ssl: bool | None = None,
        tag_name: str | None = None,
    ):
        settings = get_settings()
        self.url = url or settings.nautobot_url
        self.token = token or settings.nautobot_token
        self.verify_ssl = verify_ssl if verify_ssl is not None else settings.nautobot_verify_ssl
        self.tag_name = tag_name or settings.nautobot_tag_name

        if not self.url or not self.token:
            raise ValueError("Nautobot URL and token are required")

        self.api = pynautobot.api(self.url, token=self.token)
        if not self.verify_ssl:
            self.api.http_session.verify = False

        self._tag_id: str | None = None

    def test_connection(self) -> bool:
        """Test connection to Nautobot API."""
        try:
            self.api.status()
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Nautobot: {e}")
            return False

    def get_or_create_tag(self) -> str:
        """Get or create the Nova Inventory tag. Returns tag ID."""
        if self._tag_id:
            return self._tag_id

        try:
            tag = self.api.extras.tags.get(name=self.tag_name)
            if tag:
                self._tag_id = str(tag.id)
                return self._tag_id

            # Create the tag - content_types specifies which models can use this tag
            tag = self.api.extras.tags.create(
                name=self.tag_name,
                color="0000ff",
                description="Resources created/managed by Nova Inventory",
                content_types=[
                    "ipam.prefix",
                    "ipam.ipaddress",
                    "dcim.device",
                    "dcim.devicetype",
                    "dcim.interface",
                    "dcim.inventoryitem",
                    "dcim.virtualchassis",
                ],
            )
            self._tag_id = str(tag.id)
            logger.info(f"Created Nautobot tag: {self.tag_name}")
            return self._tag_id
        except Exception as e:
            logger.error(f"Failed to get/create tag: {e}")
            raise

    # -------------------------------------------------------------------------
    # Prefix/IP Operations
    # -------------------------------------------------------------------------

    def get_prefix_for_ip(self, ip_address: str) -> PrefixInfo | None:
        """
        Find the most specific prefix containing this IP.
        Returns prefix with location info, or None if no prefix found.

        Note: In Nautobot 2.x, prefixes are linked to locations through
        PrefixLocationAssignment records, not a direct location field.
        """
        try:
            ip = IPv4Address(ip_address)
            prefixes = list(self.api.ipam.prefixes.filter(contains=str(ip)))

            if not prefixes:
                return None

            # Find most specific (longest prefix length)
            best_prefix = None
            best_prefix_len = -1

            for prefix in prefixes:
                network = IPv4Network(prefix.prefix)
                if network.prefixlen > best_prefix_len:
                    best_prefix = prefix
                    best_prefix_len = network.prefixlen

            if not best_prefix:
                return None

            # Check for location via PrefixLocationAssignment
            location_id = None
            location_name = None

            # Query prefix location assignments for this prefix
            assignments = list(self.api.ipam.prefix_location_assignments.filter(
                prefix=best_prefix.id
            ))

            if assignments:
                # Use the first location assignment
                assignment = assignments[0]
                # assignment.location is a nested Record object, get its id
                if assignment.location:
                    location_id = str(assignment.location.id)
                    location_name = str(assignment.location)  # Display name

            return PrefixInfo(
                id=str(best_prefix.id),
                prefix=best_prefix.prefix,
                location_id=location_id,
                location_name=location_name,
            )
        except Exception as e:
            logger.error(f"Failed to get prefix for IP {ip_address}: {e}")
            raise

    def create_prefix(
        self,
        prefix: str,
        description: str | None = None,
        namespace: str = "Global",
    ) -> PrefixInfo:
        """Create a new prefix in Nautobot, tagged with Nova Inventory."""
        try:
            tag_id = self.get_or_create_tag()

            # Get or create the namespace
            ns = self.api.ipam.namespaces.get(name=namespace)
            if not ns:
                ns = self.api.ipam.namespaces.create(name=namespace)

            # Get a default status
            status = self.api.extras.statuses.get(name="Active")
            if not status:
                # Try to find any valid status for prefixes
                statuses = list(self.api.extras.statuses.filter(content_types="ipam.prefix"))
                status = statuses[0] if statuses else None

            create_data = {
                "prefix": prefix,
                "namespace": ns.id,
                "status": status.id if status else None,
                "tags": [tag_id],
            }
            # Only add description if explicitly provided
            if description:
                create_data["description"] = description

            new_prefix = self.api.ipam.prefixes.create(**create_data)

            logger.info(f"Created Nautobot prefix: {prefix}")
            return PrefixInfo(
                id=str(new_prefix.id),
                prefix=new_prefix.prefix,
                location_id=None,
                location_name=None,
            )
        except Exception as e:
            logger.error(f"Failed to create prefix {prefix}: {e}")
            raise

    def get_or_create_ip_address(
        self,
        ip_address: str,
        prefix_id: str | None = None,
    ) -> dict:
        """Get or create an IP address in Nautobot."""
        try:
            # Check if IP already exists
            existing = self.api.ipam.ip_addresses.get(address=ip_address)
            if existing:
                return {
                    "id": str(existing.id),
                    "address": existing.address,
                    "created": False,
                }

            tag_id = self.get_or_create_tag()

            # Get a default status
            status = self.api.extras.statuses.get(name="Active")
            if not status:
                statuses = list(self.api.extras.statuses.filter(content_types="ipam.ipaddress"))
                status = statuses[0] if statuses else None

            # Get namespace from prefix if provided, otherwise use Global
            namespace = None
            if prefix_id:
                prefix = self.api.ipam.prefixes.get(prefix_id)
                if prefix and prefix.namespace:
                    namespace = prefix.namespace.id
            if not namespace:
                ns = self.api.ipam.namespaces.get(name="Global")
                namespace = ns.id if ns else None

            # Ensure IP has /32 suffix for host
            if "/" not in ip_address:
                ip_address = f"{ip_address}/32"

            new_ip = self.api.ipam.ip_addresses.create(
                address=ip_address,
                namespace=namespace,
                status=status.id if status else None,
                tags=[tag_id],
            )

            logger.info(f"Created Nautobot IP address: {ip_address}")
            return {
                "id": str(new_ip.id),
                "address": new_ip.address,
                "created": True,
            }
        except Exception as e:
            logger.error(f"Failed to get/create IP address {ip_address}: {e}")
            raise

    # -------------------------------------------------------------------------
    # Location Operations
    # -------------------------------------------------------------------------

    def get_locations(self) -> list[LocationInfo]:
        """Get all locations from Nautobot."""
        try:
            locations = list(self.api.dcim.locations.all())
            result = []
            for loc in locations:
                parent_id = None
                parent_name = None
                if loc.parent:
                    parent_id = str(loc.parent.id)
                    parent_name = loc.parent.name
                result.append(LocationInfo(
                    id=str(loc.id),
                    name=loc.name,
                    parent_id=parent_id,
                    parent_name=parent_name,
                ))
            return result
        except Exception as e:
            logger.error(f"Failed to get locations: {e}")
            raise

    # -------------------------------------------------------------------------
    # Device Operations
    # -------------------------------------------------------------------------

    def get_or_create_manufacturer(self, name: str) -> str:
        """Get or create a manufacturer. Returns manufacturer ID."""
        if not name:
            name = "Unknown"

        try:
            manufacturer = self.api.dcim.manufacturers.get(name=name)
            if manufacturer:
                return str(manufacturer.id)

            # Manufacturers don't support tags in Nautobot
            manufacturer = self.api.dcim.manufacturers.create(
                name=name,
            )
            logger.info(f"Created Nautobot manufacturer: {name}")
            return str(manufacturer.id)
        except Exception as e:
            logger.error(f"Failed to get/create manufacturer {name}: {e}")
            raise

    def get_or_create_device_type(
        self,
        manufacturer_id: str,
        model: str,
    ) -> str:
        """Get or create a device type. Returns device type ID."""
        if not model:
            model = "Unknown"

        # Sanitize model name for Nautobot (alphanumeric, dashes, underscores only)
        import re
        sanitized_model = model.replace(" ", "-")
        sanitized_model = re.sub(r"[^a-zA-Z0-9_-]", "", sanitized_model)
        sanitized_model = re.sub(r"-+", "-", sanitized_model).strip("-")
        if not sanitized_model:
            sanitized_model = "Unknown"

        try:
            device_type = self.api.dcim.device_types.get(
                manufacturer=manufacturer_id,
                model=sanitized_model,
            )
            if device_type:
                return str(device_type.id)

            tag_id = self.get_or_create_tag()
            device_type = self.api.dcim.device_types.create(
                manufacturer=manufacturer_id,
                model=sanitized_model,
                part_number=sanitized_model,  # Use sanitized model as part number
                tags=[tag_id],
            )
            logger.info(f"Created Nautobot device type: {sanitized_model}")
            return str(device_type.id)
        except Exception as e:
            logger.error(f"Failed to get/create device type {sanitized_model}: {e}")
            raise

    def get_or_create_role(self, name: str) -> str:
        """Get or create a device role. Returns role ID."""
        if not name:
            name = "Unknown"

        try:
            role = self.api.extras.roles.get(name=name)
            if role:
                return str(role.id)

            # Roles need content_types to specify what they apply to
            # Roles don't support tags in Nautobot
            role = self.api.extras.roles.create(
                name=name,
                content_types=["dcim.device"],
                color="0000ff",
            )
            logger.info(f"Created Nautobot role: {name}")
            return str(role.id)
        except Exception as e:
            logger.error(f"Failed to get/create role {name}: {e}")
            raise

    def get_device_by_name(self, name: str) -> dict | None:
        """Get a device by name."""
        try:
            device = self.api.dcim.devices.get(name=name)
            if not device:
                return None
            return {
                "id": str(device.id),
                "name": device.name,
                "serial": device.serial,
                "location_id": str(device.location.id) if device.location else None,
            }
        except Exception as e:
            logger.error(f"Failed to get device {name}: {e}")
            raise

    def get_device_by_serial(self, serial: str) -> dict | None:
        """Get a device by serial number."""
        if not serial:
            return None
        try:
            device = self.api.dcim.devices.get(serial=serial)
            if not device:
                return None
            return {
                "id": str(device.id),
                "name": device.name,
                "serial": device.serial,
                "location_id": str(device.location.id) if device.location else None,
            }
        except Exception as e:
            logger.error(f"Failed to get device by serial {serial}: {e}")
            raise

    def create_device(
        self,
        name: str,
        device_type_id: str,
        role_id: str,
        location_id: str,
        serial: str | None = None,
        primary_ip_id: str | None = None,
    ) -> str:
        """Create a device in Nautobot. Returns device ID."""
        try:
            tag_id = self.get_or_create_tag()

            # Get a default status
            status = self.api.extras.statuses.get(name="Active")
            if not status:
                statuses = list(self.api.extras.statuses.filter(content_types="dcim.device"))
                status = statuses[0] if statuses else None

            device_data = {
                "name": name,
                "device_type": device_type_id,
                "role": role_id,
                "location": location_id,
                "status": status.id if status else None,
                "tags": [tag_id],
            }

            if serial:
                device_data["serial"] = serial

            device = self.api.dcim.devices.create(**device_data)
            logger.info(f"Created Nautobot device: {name}")

            # Assign primary IP if provided
            if primary_ip_id:
                try:
                    # Get interface status
                    iface_status = self.api.extras.statuses.get(name="Active")
                    if not iface_status:
                        iface_statuses = list(self.api.extras.statuses.filter(
                            content_types="dcim.interface"
                        ))
                        iface_status = iface_statuses[0] if iface_statuses else None

                    # First, assign the IP to an interface
                    # Create a management interface if needed
                    interface = self.api.dcim.interfaces.get(device_id=device.id, name="mgmt0")
                    if not interface:
                        interface = self.api.dcim.interfaces.create(
                            device=device.id,
                            name="mgmt0",
                            type="virtual",
                            status=iface_status.id if iface_status else None,
                            tags=[tag_id],
                        )

                    # Assign IP to interface using IPAddressToInterface
                    # In Nautobot 2.x, IP-to-interface assignment uses a separate model
                    ip = self.api.ipam.ip_addresses.get(primary_ip_id)
                    if ip:
                        # Create IP to interface assignment
                        try:
                            self.api.ipam.ip_address_to_interface.create(
                                ip_address=ip.id,
                                interface=interface.id,
                            )
                        except Exception:
                            # May already exist or use different API
                            pass

                        # Set as primary IP on device
                        device.primary_ip4 = ip.id
                        device.save()
                except Exception as e:
                    logger.warning(f"Failed to assign primary IP to device: {e}")

            return str(device.id)
        except Exception as e:
            logger.error(f"Failed to create device {name}: {e}")
            raise

    def update_device(
        self,
        nautobot_id: str,
        name: str | None = None,
        serial: str | None = None,
        primary_ip_id: str | None = None,
        status: str | None = None,
    ) -> bool:
        """Update an existing device in Nautobot."""
        try:
            device = self.api.dcim.devices.get(nautobot_id)
            if not device:
                logger.warning(f"Device not found in Nautobot: {nautobot_id}")
                return False

            if name and device.name != name:
                device.name = name
                device.save()

            if serial and device.serial != serial:
                device.serial = serial
                device.save()

            if status:
                # Get status by name
                status_obj = self.api.extras.statuses.get(name=status)
                if not status_obj:
                    # Try common status names
                    status_map = {
                        "offline": ["Offline", "Failed", "Decommissioned"],
                        "active": ["Active", "Online"],
                    }
                    for alt_name in status_map.get(status.lower(), []):
                        status_obj = self.api.extras.statuses.get(name=alt_name)
                        if status_obj:
                            break
                if status_obj and str(device.status) != str(status_obj):
                    device.status = status_obj.id
                    device.save()
                    logger.info(f"Updated device {nautobot_id} status to {status}")

            if primary_ip_id:
                # Need to assign IP to an interface first
                tag_id = self.get_or_create_tag()

                # Get interface status
                iface_status = self.api.extras.statuses.get(name="Active")
                if not iface_status:
                    iface_statuses = list(self.api.extras.statuses.filter(
                        content_types="dcim.interface"
                    ))
                    iface_status = iface_statuses[0] if iface_statuses else None

                # Get or create management interface
                interface = self.api.dcim.interfaces.get(device_id=device.id, name="mgmt0")
                if not interface:
                    interface = self.api.dcim.interfaces.create(
                        device=device.id,
                        name="mgmt0",
                        type="virtual",
                        status=iface_status.id if iface_status else None,
                        tags=[tag_id],
                    )

                # Get the IP
                ip = self.api.ipam.ip_addresses.get(primary_ip_id)
                if ip:
                    # Create IP to interface assignment
                    try:
                        self.api.ipam.ip_address_to_interface.create(
                            ip_address=ip.id,
                            interface=interface.id,
                        )
                    except Exception:
                        # May already exist
                        pass

                    # Set as primary IP on device
                    device.primary_ip4 = ip.id
                    device.save()

            logger.info(f"Updated Nautobot device: {nautobot_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to update device {nautobot_id}: {e}")
            raise

    # -------------------------------------------------------------------------
    # Virtual Chassis Operations
    # -------------------------------------------------------------------------

    def get_or_create_virtual_chassis(
        self,
        name: str,
        master_device_id: str | None = None,
    ) -> str:
        """Get or create a virtual chassis. Returns virtual chassis ID."""
        try:
            # Check if virtual chassis already exists
            vc = self.api.dcim.virtual_chassis.get(name=name)
            if vc:
                return str(vc.id)

            tag_id = self.get_or_create_tag()

            vc_data = {
                "name": name,
                "tags": [tag_id],
            }

            if master_device_id:
                vc_data["master"] = master_device_id

            vc = self.api.dcim.virtual_chassis.create(**vc_data)
            logger.info(f"Created Nautobot virtual chassis: {name}")
            return str(vc.id)
        except Exception as e:
            logger.error(f"Failed to get/create virtual chassis {name}: {e}")
            raise

    def add_device_to_virtual_chassis(
        self,
        device_id: str,
        virtual_chassis_id: str,
        vc_position: int,
        vc_priority: int | None = None,
    ) -> bool:
        """Add a device to a virtual chassis."""
        try:
            device = self.api.dcim.devices.get(device_id)
            if not device:
                logger.warning(f"Device not found: {device_id}")
                return False

            device.virtual_chassis = virtual_chassis_id
            device.vc_position = vc_position
            if vc_priority is not None:
                device.vc_priority = vc_priority
            device.save()

            logger.info(f"Added device {device_id} to virtual chassis at position {vc_position}")
            return True
        except Exception as e:
            logger.error(f"Failed to add device to virtual chassis: {e}")
            raise

    def remove_device_from_virtual_chassis(self, device_id: str) -> bool:
        """Remove a device from its virtual chassis."""
        try:
            device = self.api.dcim.devices.get(device_id)
            if not device:
                logger.warning(f"Device not found: {device_id}")
                return False

            if not device.virtual_chassis:
                return True  # Already not in a VC

            device.virtual_chassis = None
            device.vc_position = None
            device.vc_priority = None
            device.save()

            logger.info(f"Removed device {device_id} from virtual chassis")
            return True
        except Exception as e:
            logger.error(f"Failed to remove device from virtual chassis: {e}")
            raise

    def set_virtual_chassis_master(
        self,
        virtual_chassis_id: str,
        master_device_id: str,
    ) -> bool:
        """Set the master device for a virtual chassis."""
        try:
            vc = self.api.dcim.virtual_chassis.get(virtual_chassis_id)
            if not vc:
                logger.warning(f"Virtual chassis not found: {virtual_chassis_id}")
                return False

            vc.master = master_device_id
            vc.save()

            logger.info(f"Set master device for virtual chassis {virtual_chassis_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to set virtual chassis master: {e}")
            raise

    def create_stack_device(
        self,
        name: str,
        device_type_id: str,
        role_id: str,
        location_id: str,
        serial: str | None = None,
        vc_position: int | None = None,
    ) -> str:
        """
        Create a device that will be part of a stack (no primary IP).
        Returns device ID.
        """
        try:
            tag_id = self.get_or_create_tag()

            # Get a default status
            status = self.api.extras.statuses.get(name="Active")
            if not status:
                statuses = list(self.api.extras.statuses.filter(content_types="dcim.device"))
                status = statuses[0] if statuses else None

            device_data = {
                "name": name,
                "device_type": device_type_id,
                "role": role_id,
                "location": location_id,
                "status": status.id if status else None,
                "tags": [tag_id],
            }

            if serial:
                device_data["serial"] = serial

            device = self.api.dcim.devices.create(**device_data)
            logger.info(f"Created Nautobot stack device: {name}")

            return str(device.id)
        except Exception as e:
            logger.error(f"Failed to create stack device {name}: {e}")
            raise

    # -------------------------------------------------------------------------
    # Inventory Item Operations
    # -------------------------------------------------------------------------

    def sync_inventory_items(
        self,
        device_id: str,
        inventory_data: dict,
        manufacturer_id: str,
    ) -> dict:
        """
        Sync inventory items (components) to a device in Nautobot.

        Args:
            device_id: Nautobot device UUID
            inventory_data: Inventory dict from device.metadata_['inventory']
            manufacturer_id: Default manufacturer ID to use for items

        Returns:
            Dict with counts: created, updated, removed (marked in description)
        """
        result = {"created": 0, "updated": 0, "removed": 0, "errors": []}

        if not inventory_data:
            return result

        try:
            tag_id = self.get_or_create_tag()

            # Get existing inventory items for this device
            existing_items = {
                item.serial: item
                for item in self.api.dcim.inventory_items.filter(device=device_id)
                if item.serial
            }

            # Collect all components to sync
            components_to_sync = []

            # Add modules
            for module in inventory_data.get("modules", []):
                if module.get("serial") and not module.get("removed_at"):
                    components_to_sync.append({
                        "name": module.get("name") or module.get("description") or "Module",
                        "part_id": module.get("model") or "",
                        "serial": module.get("serial"),
                        "description": module.get("description") or "",
                        "component_type": "Module",
                    })

            # Add power supplies
            for psu in inventory_data.get("power_supplies", []):
                if psu.get("serial") and not psu.get("removed_at"):
                    components_to_sync.append({
                        "name": psu.get("name") or psu.get("description") or "Power Supply",
                        "part_id": psu.get("model") or "",
                        "serial": psu.get("serial"),
                        "description": psu.get("description") or "",
                        "component_type": "Power Supply",
                    })

            # Add fans
            for fan in inventory_data.get("fans", []):
                if fan.get("serial") and not fan.get("removed_at"):
                    components_to_sync.append({
                        "name": fan.get("name") or fan.get("description") or "Fan",
                        "part_id": fan.get("model") or "",
                        "serial": fan.get("serial"),
                        "description": fan.get("description") or "",
                        "component_type": "Fan",
                    })

            # Add stack members (excluding the main chassis)
            for stack in inventory_data.get("stack_members", []):
                if stack.get("serial") and not stack.get("removed_at"):
                    components_to_sync.append({
                        "name": stack.get("name") or stack.get("description") or "Stack Member",
                        "part_id": stack.get("model") or "",
                        "serial": stack.get("serial"),
                        "description": stack.get("description") or "",
                        "component_type": "Stack Member",
                    })

            # Track which serials we've seen
            seen_serials = set()

            # Create or update inventory items
            for component in components_to_sync:
                serial = component["serial"]
                seen_serials.add(serial)

                try:
                    if serial in existing_items:
                        # Update existing item if needed
                        item = existing_items[serial]
                        needs_update = False

                        if item.name != component["name"]:
                            item.name = component["name"]
                            needs_update = True
                        if item.part_id != component["part_id"]:
                            item.part_id = component["part_id"]
                            needs_update = True

                        if needs_update:
                            item.save()
                            result["updated"] += 1
                    else:
                        # Create new inventory item
                        try:
                            self.api.dcim.inventory_items.create(
                                device=device_id,
                                name=component["name"],
                                part_id=component["part_id"],
                                serial=serial,
                                manufacturer=manufacturer_id,
                                tags=[tag_id],
                            )
                        except Exception:
                            # Try without tags if tag application fails
                            self.api.dcim.inventory_items.create(
                                device=device_id,
                                name=component["name"],
                                part_id=component["part_id"],
                                serial=serial,
                                manufacturer=manufacturer_id,
                            )
                        result["created"] += 1
                except Exception as e:
                    result["errors"].append(f"{component['name']}: {str(e)}")

            # Mark removed inventory items in description field
            from datetime import datetime
            removed_timestamp = datetime.now().strftime("%Y-%m-%d")

            for serial, item in existing_items.items():
                if serial not in seen_serials:
                    # Only mark items we created (tagged with our tag)
                    item_tags = [str(t) if hasattr(t, 'id') else str(t) for t in (item.tags or [])]
                    if tag_id in item_tags:
                        try:
                            # Check if already marked as removed
                            current_desc = item.description or ""
                            if not current_desc.startswith("REMOVED:"):
                                item.description = f"REMOVED: {removed_timestamp}"
                                item.save()
                                result["removed"] += 1
                                logger.info(f"Marked inventory item {serial} as removed")
                        except Exception as e:
                            result["errors"].append(f"Mark removed {serial}: {str(e)}")

            logger.info(
                f"Synced inventory items for device {device_id}: "
                f"created={result['created']}, updated={result['updated']}, removed={result['removed']}"
            )

        except Exception as e:
            logger.error(f"Failed to sync inventory items: {e}")
            result["errors"].append(str(e))

        return result


def get_nautobot_client() -> NautobotClient | None:
    """Get a Nautobot client if configured, otherwise return None."""
    settings = get_settings()
    if not settings.nautobot_url or not settings.nautobot_token:
        return None
    return NautobotClient()
