"""
Mapping between local device data and Nautobot format.
"""
import re

from src.db.models import Device


def sanitize_nautobot_name(name: str | None) -> str:
    """
    Sanitize a name for Nautobot (manufacturer/model).

    Nautobot only allows alphanumeric, dashes, and underscores.
    Spaces are replaced with dashes, other special chars removed.
    """
    if not name:
        return "Unknown"

    # Replace spaces with dashes
    name = name.replace(" ", "-")
    # Remove any character that's not alphanumeric, dash, or underscore
    name = re.sub(r"[^a-zA-Z0-9_-]", "", name)
    # Remove consecutive dashes
    name = re.sub(r"-+", "-", name)
    # Remove leading/trailing dashes
    name = name.strip("-")

    return name if name else "Unknown"


# Mapping from our device_type to Nautobot role names
DEVICE_TYPE_TO_ROLE = {
    "router": "Router",
    "switch": "Switch",
    "firewall": "Firewall",
    "access point": "Access Point",
    "wireless controller": "Wireless Controller",
    "load balancer": "Load Balancer",
    "console appliance": "Console Server",
    "ipam": "Network Services",
    "server": "Server",
    "pdu": "PDU",
    "ups": "UPS",
}


def map_device_type_to_role(device_type: str | None) -> str:
    """Map our device_type to Nautobot role name."""
    if not device_type:
        return "Unknown"

    # Try exact match first (case-insensitive)
    lower_type = device_type.lower()
    if lower_type in DEVICE_TYPE_TO_ROLE:
        return DEVICE_TYPE_TO_ROLE[lower_type]

    # Try partial match
    for key, value in DEVICE_TYPE_TO_ROLE.items():
        if key in lower_type or lower_type in key:
            return value

    # Return the original with proper casing
    return device_type.title()


def get_device_name(device: Device) -> str:
    """Get the name to use for a device in Nautobot."""
    if device.hostname:
        # Use hostname, but strip domain if present
        hostname = device.hostname.split(".")[0]
        return hostname
    # Fall back to IP address
    return str(device.ip_address)


def map_device_to_nautobot(device: Device, location_id: str) -> dict:
    """
    Convert local Device to Nautobot device payload.

    Returns a dict with the fields needed to create/update a device in Nautobot.
    """
    return {
        "name": get_device_name(device),
        "manufacturer": sanitize_nautobot_name(device.vendor),
        "model": sanitize_nautobot_name(device.model),
        "role": map_device_type_to_role(device.device_type),
        "location_id": location_id,
        "serial": device.serial_number,
        "ip_address": str(device.ip_address),
    }
