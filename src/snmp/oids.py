"""
Standard and vendor-specific OID constants.
"""


class SystemOIDs:
    """Standard MIB-II System Group OIDs."""
    SYS_DESCR = "1.3.6.1.2.1.1.1.0"
    SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
    SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
    SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
    SYS_NAME = "1.3.6.1.2.1.1.5.0"
    SYS_LOCATION = "1.3.6.1.2.1.1.6.0"


class EntityOIDs:
    """Entity MIB OIDs for hardware information."""
    ENT_PHYSICAL_DESCR = "1.3.6.1.2.1.47.1.1.1.1.2"
    ENT_PHYSICAL_NAME = "1.3.6.1.2.1.47.1.1.1.1.7"
    ENT_PHYSICAL_SOFTWARE_REV = "1.3.6.1.2.1.47.1.1.1.1.10"
    ENT_PHYSICAL_SERIAL = "1.3.6.1.2.1.47.1.1.1.1.11"
    ENT_PHYSICAL_MODEL = "1.3.6.1.2.1.47.1.1.1.1.13"


class EnterpriseNumbers:
    """IANA Private Enterprise Numbers for vendor identification."""
    CISCO = 9
    JUNIPER = 2636
    HP = 11
    ARUBA = 14823
    F5 = 3375
    FORTINET = 12356
    PALO_ALTO = 25461
    CHECKPOINT = 2620
    ARISTA = 30065
    INFOBLOX = 7779

    @classmethod
    def get_prefix(cls, vendor_id: int) -> str:
        """Get the OID prefix for a vendor enterprise number."""
        return f"1.3.6.1.4.1.{vendor_id}"

    @classmethod
    def get_all(cls) -> dict[str, int]:
        """Return all enterprise numbers as a dict."""
        return {
            "cisco": cls.CISCO,
            "juniper": cls.JUNIPER,
            "hp": cls.HP,
            "aruba": cls.ARUBA,
            "f5": cls.F5,
            "fortinet": cls.FORTINET,
            "paloalto": cls.PALO_ALTO,
            "checkpoint": cls.CHECKPOINT,
            "arista": cls.ARISTA,
            "infoblox": cls.INFOBLOX,
        }
