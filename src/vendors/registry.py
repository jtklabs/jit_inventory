"""
Vendor handler registration and lookup.
"""
from typing import Type

from src.vendors.base import VendorHandler


class VendorRegistry:
    """
    Central registry for vendor handlers.
    Enables automatic vendor detection and handler routing.
    """

    _handlers: dict[str, VendorHandler] = {}
    _enterprise_map: dict[int, str] = {}
    _initialized: bool = False

    @classmethod
    def register(cls, handler_class: Type[VendorHandler]) -> None:
        """Register a vendor handler."""
        handler = handler_class()
        cls._handlers[handler.vendor_name] = handler
        cls._enterprise_map[handler.enterprise_id] = handler.vendor_name

    @classmethod
    def get_handler(cls, vendor_name: str) -> VendorHandler | None:
        """Get handler by vendor name."""
        cls._ensure_initialized()
        return cls._handlers.get(vendor_name.lower())

    @classmethod
    def detect_vendor(cls, sys_object_id: str) -> VendorHandler | None:
        """
        Detect vendor from sysObjectID and return appropriate handler.
        """
        cls._ensure_initialized()
        for handler in cls._handlers.values():
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

        # Future vendor handlers will be registered here:
        # from src.vendors.juniper.collector import JuniperHandler
        # from src.vendors.fortinet.collector import FortinetHandler
        # from src.vendors.f5.collector import F5Handler
        # from src.vendors.aruba.collector import ArubaHandler
        # from src.vendors.infoblox.collector import InfobloxHandler
        # from src.vendors.checkpoint.collector import CheckpointHandler
