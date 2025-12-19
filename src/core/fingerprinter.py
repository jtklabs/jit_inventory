"""
Device fingerprinting logic - detects vendor and device type from SNMP.
"""
from dataclasses import dataclass

from src.snmp.client import SNMPClient, SNMPCredential, SNMPError
from src.snmp.oids import SystemOIDs
from src.vendors.base import DeviceInfo
from src.vendors.registry import VendorRegistry


@dataclass
class FingerprintResult:
    """Result of device fingerprinting."""

    success: bool
    device_info: DeviceInfo | None = None
    error: str | None = None
    raw_sys_descr: str | None = None
    raw_sys_object_id: str | None = None


class DeviceFingerprinter:
    """
    Fingerprints network devices using SNMP sysObjectID and sysDescr.
    """

    def __init__(self, snmp_client: SNMPClient):
        self.snmp_client = snmp_client

    async def fingerprint(self, credential: SNMPCredential) -> FingerprintResult:
        """
        Perform device fingerprinting.

        1. Query sysObjectID and sysDescr
        2. Match against vendor registry
        3. Use vendor handler to identify device type/model
        """
        try:
            # Get system OIDs
            response = await self.snmp_client.get_bulk(
                [
                    SystemOIDs.SYS_OBJECT_ID,
                    SystemOIDs.SYS_DESCR,
                    SystemOIDs.SYS_NAME,
                ],
                credential,
            )

            # Extract values - handle both full OID and short OID keys
            sys_object_id = None
            sys_descr = None
            sys_name = None

            for key, value in response.items():
                if SystemOIDs.SYS_OBJECT_ID in key or key.endswith(".1.2.0"):
                    sys_object_id = value
                elif SystemOIDs.SYS_DESCR in key or key.endswith(".1.1.0"):
                    sys_descr = value
                elif SystemOIDs.SYS_NAME in key or key.endswith(".1.5.0"):
                    sys_name = value

            if not sys_object_id:
                return FingerprintResult(
                    success=False,
                    error="Could not retrieve sysObjectID",
                    raw_sys_descr=sys_descr,
                )

            # Detect vendor
            handler = VendorRegistry.detect_vendor(sys_object_id)

            if not handler:
                # Unknown vendor - still return what we know
                return FingerprintResult(
                    success=True,
                    device_info=DeviceInfo(
                        ip_address=self.snmp_client.host,
                        hostname=sys_name,
                        vendor="unknown",
                        sys_object_id=sys_object_id,
                        sys_description=sys_descr,
                    ),
                    raw_sys_object_id=sys_object_id,
                    raw_sys_descr=sys_descr,
                )

            # Identify device type using vendor handler
            device_type_info = handler.identify_device_type(sys_object_id, sys_descr)

            return FingerprintResult(
                success=True,
                device_info=DeviceInfo(
                    ip_address=self.snmp_client.host,
                    hostname=sys_name,
                    vendor=handler.vendor_name,
                    device_type=device_type_info.get("device_type"),
                    platform=device_type_info.get("platform"),
                    model=device_type_info.get("model"),
                    sys_object_id=sys_object_id,
                    sys_description=sys_descr,
                ),
                raw_sys_object_id=sys_object_id,
                raw_sys_descr=sys_descr,
            )

        except SNMPError as e:
            return FingerprintResult(success=False, error=str(e))
        except Exception as e:
            return FingerprintResult(success=False, error=f"Unexpected error: {str(e)}")
