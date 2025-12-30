"""
Vendor handler registration and lookup.
"""
from typing import Type

from src.vendors.base import VendorHandler


class VendorRegistry:
    """
    Central registry for vendor handlers.
    Enables automatic vendor detection and handler routing.

    Supports multiple handlers per vendor (e.g., Aruba WLC and ClearPass both
    return vendor_name="aruba" but have different detection logic).
    """

    _handlers: dict[str, VendorHandler] = {}
    _detection_handlers: list[VendorHandler] = []  # Ordered list for detection
    _enterprise_map: dict[int, str] = {}
    _initialized: bool = False

    @classmethod
    def register(cls, handler_class: Type[VendorHandler], detection_priority: bool = True) -> None:
        """
        Register a vendor handler.

        Args:
            handler_class: The handler class to register
            detection_priority: If True, add to front of detection list (checked first)
        """
        handler = handler_class()
        # Store by vendor name (may overwrite if same name)
        cls._handlers[handler.vendor_name] = handler
        cls._enterprise_map[handler.enterprise_id] = handler.vendor_name
        # Add to detection list (more specific handlers should be added first)
        if detection_priority:
            cls._detection_handlers.insert(0, handler)
        else:
            cls._detection_handlers.append(handler)

    @classmethod
    def get_handler(cls, vendor_name: str) -> VendorHandler | None:
        """Get handler by vendor name."""
        cls._ensure_initialized()
        return cls._handlers.get(vendor_name.lower())

    @classmethod
    def detect_vendor(cls, sys_object_id: str) -> VendorHandler | None:
        """
        Detect vendor from sysObjectID and return appropriate handler.

        Checks handlers in registration order - more specific handlers
        (like ClearPass) should be registered before general ones (like Aruba WLC).
        """
        cls._ensure_initialized()
        for handler in cls._detection_handlers:
            if handler.matches_sys_object_id(sys_object_id):
                return handler
        return None

    @classmethod
    def get_all_vendors(cls) -> list[str]:
        """Return list of registered vendor names."""
        cls._ensure_initialized()
        return list(cls._handlers.keys())

    @classmethod
    def _ensure_initialized(cls) -> None:
        """Ensure handlers are registered."""
        if not cls._initialized:
            cls._register_all_handlers()
            cls._initialized = True

    @classmethod
    def _register_all_handlers(cls) -> None:
        """Register all available vendor handlers."""
        # Import and register Cisco handler
        from src.vendors.cisco.collector import CiscoHandler

        cls.register(CiscoHandler)

        # Import and register Arista handler
        from src.vendors.arista.collector import AristaHandler

        cls.register(AristaHandler)

        # Import and register Palo Alto handler
        from src.vendors.paloalto.collector import PaloAltoHandler

        cls.register(PaloAltoHandler)

        # Import and register Aruba WLC handler first (lower priority)
        from src.vendors.aruba.collector import ArubaHandler

        cls.register(ArubaHandler)

        # Import and register ClearPass handler last (higher priority, checked first)
        # ClearPass has more specific OID match (1.3.6.1.4.1.14823.1.6.*)
        from src.vendors.aruba.clearpass import ClearPassHandler

        cls.register(ClearPassHandler)

        # Import and register Juniper handler
        from src.vendors.juniper.collector import JuniperHandler

        cls.register(JuniperHandler)

        # Import and register Fortinet FortiGate handler
        from src.vendors.fortinet.collector import FortinetHandler

        cls.register(FortinetHandler)

        # Import and register F5 BIG-IP handler
        from src.vendors.f5.collector import F5Handler

        cls.register(F5Handler)

        # Import and register Infoblox handler
        from src.vendors.infoblox.collector import InfobloxHandler

        cls.register(InfobloxHandler)

        # Import and register Check Point handler
        from src.vendors.checkpoint.collector import CheckpointHandler

        cls.register(CheckpointHandler)

        # Import and register Opengear handler
        from src.vendors.opengear.collector import OpengearHandler

        cls.register(OpengearHandler)

        # Import and register Dell EMC Networking handler
        from src.vendors.dell.collector import DellHandler

        cls.register(DellHandler)
