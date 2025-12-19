"""
Main scanner orchestrator - coordinates fingerprinting and data collection.
"""
import time
from dataclasses import dataclass
from datetime import datetime

from src.config.settings import get_settings
from src.db.connection import get_db_session
from src.db.repositories.device import DeviceRepository
from src.db.repositories.scan import ScanHistoryRepository
from src.snmp.client import SNMPClient, SNMPCredential, SNMPError
from src.vendors.base import DeviceInfo
from src.vendors.registry import VendorRegistry
from src.core.fingerprinter import DeviceFingerprinter


class ScanError(Exception):
    """Raised when a scan operation fails."""

    pass


@dataclass
class ScanResult:
    """Result of a device scan."""

    success: bool
    device_info: DeviceInfo | None = None
    error: str | None = None
    duration_ms: int = 0
    scan_history_id: str | None = None
    credential_profile_name: str | None = None  # Profile that worked


class DeviceScanner:
    """
    Orchestrates the complete device scanning workflow.
    """

    def __init__(
        self,
        timeout: int | None = None,
        retries: int | None = None,
    ):
        settings = get_settings()
        self.timeout = timeout or settings.snmp_timeout
        self.retries = retries or settings.snmp_retries

    async def scan_device(
        self,
        ip_address: str,
        credential: SNMPCredential,
        port: int = 161,
        scan_type: str = "single",
        credential_profile_name: str | None = None,
        save_to_db: bool = True,
    ) -> ScanResult:
        """
        Perform complete device scan:
        1. Fingerprint device (get sysObjectID, detect vendor)
        2. Collect vendor-specific data (serial, version, etc.)
        3. Save to database
        4. Return unified DeviceInfo
        """
        start_time = time.time()

        client = SNMPClient(
            host=ip_address,
            port=port,
            timeout=self.timeout,
            retries=self.retries,
        )

        try:
            # Step 1: Fingerprint
            fingerprinter = DeviceFingerprinter(client)
            fp_result = await fingerprinter.fingerprint(credential)

            if not fp_result.success:
                duration_ms = int((time.time() - start_time) * 1000)
                error_msg = fp_result.error or "Fingerprinting failed"

                # Save failed scan to history
                scan_id = None
                if save_to_db:
                    scan_id = self._save_failed_scan(
                        ip_address=ip_address,
                        scan_type=scan_type,
                        error_message=error_msg,
                        duration_ms=duration_ms,
                        credential_profile_name=credential_profile_name,
                        credential=credential,
                    )

                return ScanResult(
                    success=False,
                    error=error_msg,
                    duration_ms=duration_ms,
                    scan_history_id=scan_id,
                )

            device_info = fp_result.device_info
            if device_info is None:
                raise ScanError("Fingerprinting returned no device info")

            # Step 2: Collect vendor-specific data using Entity MIB table walking
            # This approach finds chassis info by entity class rather than hardcoded
            # indices, making it work across different device models
            if device_info.vendor and device_info.vendor != "unknown":
                handler = VendorRegistry.get_handler(device_info.vendor)
                if handler:
                    try:
                        walk_oids = handler.get_entity_walk_oids()
                        walk_results: dict[str, list[tuple[str, str]]] = {}

                        for name, base_oid in walk_oids.items():
                            try:
                                results = await client.walk(base_oid, credential, max_rows=50)
                                walk_results[name] = results
                            except SNMPError:
                                walk_results[name] = []

                        # Parse using entity class-based detection
                        parsed = handler.parse_basic_info_from_entity_walk(
                            walk_results, sys_descr=device_info.sys_description
                        )

                        # Update device info - prefer Entity MIB data over sysDescr
                        if parsed.get("serial_number"):
                            device_info.serial_number = parsed["serial_number"]
                        if parsed.get("software_version"):
                            device_info.software_version = parsed["software_version"]
                        if parsed.get("model"):
                            device_info.model = parsed["model"]

                        # Store raw walk data for debugging
                        device_info.raw_data = {
                            name: [(oid, val) for oid, val in results]
                            for name, results in walk_results.items()
                            if results
                        }

                    except SNMPError:
                        # Continue with fingerprint data if collection fails
                        pass

            duration_ms = int((time.time() - start_time) * 1000)

            # Step 3: Save to database
            scan_id = None
            if save_to_db:
                scan_id = self._save_successful_scan(
                    device_info=device_info,
                    scan_type=scan_type,
                    duration_ms=duration_ms,
                    credential_profile_name=credential_profile_name,
                    credential=credential,
                )

            return ScanResult(
                success=True,
                device_info=device_info,
                duration_ms=duration_ms,
                scan_history_id=scan_id,
            )

        except SNMPError as e:
            duration_ms = int((time.time() - start_time) * 1000)
            error_msg = str(e)

            scan_id = None
            if save_to_db:
                scan_id = self._save_failed_scan(
                    ip_address=ip_address,
                    scan_type=scan_type,
                    error_message=error_msg,
                    duration_ms=duration_ms,
                    credential_profile_name=credential_profile_name,
                    credential=credential,
                )

            return ScanResult(
                success=False,
                error=error_msg,
                duration_ms=duration_ms,
                scan_history_id=scan_id,
            )

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            error_msg = f"Unexpected error: {str(e)}"

            scan_id = None
            if save_to_db:
                scan_id = self._save_failed_scan(
                    ip_address=ip_address,
                    scan_type=scan_type,
                    error_message=error_msg,
                    duration_ms=duration_ms,
                    credential_profile_name=credential_profile_name,
                    credential=credential,
                )

            return ScanResult(
                success=False,
                error=error_msg,
                duration_ms=duration_ms,
                scan_history_id=scan_id,
            )

    async def scan_device_auto_discover(
        self,
        ip_address: str,
        profiles: list,
        port: int = 161,
        scan_type: str = "single",
        save_to_db: bool = True,
    ) -> ScanResult:
        """
        Try multiple credential profiles in priority order until one works.

        Args:
            ip_address: Target device IP
            profiles: List of credential profile objects, ordered by priority
            port: SNMP port
            scan_type: Type of scan for history
            save_to_db: Whether to save results to database

        Returns:
            ScanResult with credential_profile_name set to the working profile
        """
        if not profiles:
            return ScanResult(
                success=False,
                error="No credential profiles available",
                duration_ms=0,
            )

        errors = []
        total_start_time = time.time()

        for profile in profiles:
            try:
                result = await self.scan_device(
                    ip_address=ip_address,
                    credential=profile.to_snmp_credential(),
                    port=port,
                    scan_type=scan_type,
                    credential_profile_name=profile.name,
                    save_to_db=save_to_db,
                )

                if result.success:
                    result.credential_profile_name = profile.name
                    return result
                else:
                    errors.append(f"{profile.name}: {result.error}")

            except Exception as e:
                errors.append(f"{profile.name}: {str(e)}")

        # All profiles failed
        duration_ms = int((time.time() - total_start_time) * 1000)
        error_msg = f"All {len(profiles)} credential profiles failed: " + "; ".join(errors[:3])
        if len(errors) > 3:
            error_msg += f" (and {len(errors) - 3} more)"

        return ScanResult(
            success=False,
            error=error_msg,
            duration_ms=duration_ms,
        )

    def _get_snmp_version(self, credential: SNMPCredential) -> str:
        """Determine SNMP version from credential type."""
        from src.snmp.client import SNMPv2cCredential

        return "v2c" if isinstance(credential, SNMPv2cCredential) else "v3"

    def _save_successful_scan(
        self,
        device_info: DeviceInfo,
        scan_type: str,
        duration_ms: int,
        credential_profile_name: str | None,
        credential: SNMPCredential,
    ) -> str | None:
        """Save successful scan to database."""
        try:
            with get_db_session() as session:
                # Update or create device
                device_repo = DeviceRepository(session)
                device, created = device_repo.update_or_create(
                    ip_address=device_info.ip_address,
                    hostname=device_info.hostname,
                    vendor=device_info.vendor,
                    device_type=device_info.device_type,
                    platform=device_info.platform,
                    model=device_info.model,
                    serial_number=device_info.serial_number,
                    software_version=device_info.software_version,
                    sys_object_id=device_info.sys_object_id,
                    sys_description=device_info.sys_description,
                    metadata=device_info.raw_data if device_info.raw_data else None,
                    credential_profile_name=credential_profile_name,
                )

                # Create scan history
                scan_repo = ScanHistoryRepository(session)
                scan = scan_repo.create(
                    ip_address=device_info.ip_address,
                    scan_type=scan_type,
                    scan_status="success",
                    device_id=device.id,
                    hostname=device_info.hostname,
                    vendor=device_info.vendor,
                    device_type=device_info.device_type,
                    platform=device_info.platform,
                    model=device_info.model,
                    serial_number=device_info.serial_number,
                    software_version=device_info.software_version,
                    sys_object_id=device_info.sys_object_id,
                    sys_description=device_info.sys_description,
                    raw_snmp_data=device_info.raw_data,
                    duration_ms=duration_ms,
                    credential_profile_name=credential_profile_name,
                    snmp_version=self._get_snmp_version(credential),
                )

                return scan.id

        except Exception:
            # Don't fail the scan if DB save fails
            return None

    def _save_failed_scan(
        self,
        ip_address: str,
        scan_type: str,
        error_message: str,
        duration_ms: int,
        credential_profile_name: str | None,
        credential: SNMPCredential,
    ) -> str | None:
        """Save failed scan to database."""
        try:
            with get_db_session() as session:
                scan_repo = ScanHistoryRepository(session)
                scan = scan_repo.create(
                    ip_address=ip_address,
                    scan_type=scan_type,
                    scan_status="failed",
                    error_message=error_message,
                    duration_ms=duration_ms,
                    credential_profile_name=credential_profile_name,
                    snmp_version=self._get_snmp_version(credential),
                )
                return scan.id

        except Exception:
            return None
