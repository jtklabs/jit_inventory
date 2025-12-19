"""
IP address and CIDR utilities.
"""
import re
from ipaddress import IPv4Address, IPv4Network, AddressValueError, NetmaskValueError


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        IPv4Address(ip.strip())
        return True
    except (AddressValueError, ValueError):
        return False


def is_valid_cidr(cidr: str) -> bool:
    """Check if string is a valid CIDR notation."""
    try:
        IPv4Network(cidr.strip(), strict=False)
        return True
    except (AddressValueError, NetmaskValueError, ValueError):
        return False


def expand_cidr(cidr: str) -> list[str]:
    """
    Expand CIDR notation to list of IP addresses.
    Excludes network and broadcast addresses for networks larger than /31.
    """
    try:
        network = IPv4Network(cidr.strip(), strict=False)
        if network.prefixlen >= 31:
            # For /31 and /32, return all addresses
            return [str(ip) for ip in network]
        # Exclude network and broadcast addresses
        return [str(ip) for ip in network.hosts()]
    except (AddressValueError, NetmaskValueError, ValueError):
        return []


def parse_ip_list(text: str) -> list[str]:
    """
    Parse text containing IP addresses (one per line or comma-separated).
    Returns list of valid IP addresses.
    """
    # Split by newlines and commas
    parts = re.split(r"[\n,;]+", text)

    ips = []
    for part in parts:
        ip = part.strip()
        if ip and is_valid_ip(ip):
            ips.append(ip)

    return ips


def parse_targets(text: str) -> list[str]:
    """
    Parse text that may contain IP addresses, CIDR ranges, or a mix.
    Returns expanded list of all IP addresses.
    """
    # Split by newlines and commas
    parts = re.split(r"[\n,;]+", text)

    ips = []
    for part in parts:
        target = part.strip()
        if not target:
            continue

        if "/" in target and is_valid_cidr(target):
            # CIDR range
            ips.extend(expand_cidr(target))
        elif is_valid_ip(target):
            # Single IP
            ips.append(target)

    # Remove duplicates while preserving order
    seen = set()
    unique_ips = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)

    return unique_ips


def estimate_target_count(text: str) -> int:
    """
    Estimate total number of targets without fully expanding.
    Useful for UI feedback before processing.
    """
    parts = re.split(r"[\n,;]+", text)

    count = 0
    for part in parts:
        target = part.strip()
        if not target:
            continue

        if "/" in target:
            try:
                network = IPv4Network(target.strip(), strict=False)
                if network.prefixlen >= 31:
                    count += network.num_addresses
                else:
                    # Exclude network and broadcast
                    count += max(0, network.num_addresses - 2)
            except (AddressValueError, NetmaskValueError, ValueError):
                pass
        elif is_valid_ip(target):
            count += 1

    return count
