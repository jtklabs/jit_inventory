"""
SNMP Client wrapper using pysnmp library.
Handles both SNMPv2c and SNMPv3 operations.
"""
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
    bulk_cmd,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmDESPrivProtocol,
    usmAesCfb128Protocol,
    usmAesCfb256Protocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)


class AuthProtocol(str, Enum):
    """SNMPv3 authentication protocols."""
    NONE = "none"
    MD5 = "MD5"
    SHA = "SHA"
    SHA224 = "SHA-224"
    SHA256 = "SHA-256"


class PrivProtocol(str, Enum):
    """SNMPv3 privacy protocols."""
    NONE = "none"
    DES = "DES"
    AES128 = "AES-128"
    AES256 = "AES-256"


# Protocol mappings for pysnmp
AUTH_PROTOCOL_MAP = {
    AuthProtocol.NONE: usmNoAuthProtocol,
    AuthProtocol.MD5: usmHMACMD5AuthProtocol,
    AuthProtocol.SHA: usmHMACSHAAuthProtocol,
    AuthProtocol.SHA224: usmHMAC128SHA224AuthProtocol,
    AuthProtocol.SHA256: usmHMAC192SHA256AuthProtocol,
}

PRIV_PROTOCOL_MAP = {
    PrivProtocol.NONE: usmNoPrivProtocol,
    PrivProtocol.DES: usmDESPrivProtocol,
    PrivProtocol.AES128: usmAesCfb128Protocol,
    PrivProtocol.AES256: usmAesCfb256Protocol,
}


@dataclass
class SNMPv2cCredential:
    """SNMPv2c credential with community string."""
    community: str


@dataclass
class SNMPv3Credential:
    """SNMPv3 credential with auth and privacy settings."""
    username: str
    auth_protocol: AuthProtocol = AuthProtocol.NONE
    auth_password: str | None = None
    priv_protocol: PrivProtocol = PrivProtocol.NONE
    priv_password: str | None = None

    @property
    def security_level(self) -> str:
        """Return the security level based on configured protocols."""
        if self.priv_protocol != PrivProtocol.NONE and self.auth_protocol != AuthProtocol.NONE:
            return "authPriv"
        elif self.auth_protocol != AuthProtocol.NONE:
            return "authNoPriv"
        return "noAuthNoPriv"


SNMPCredential = SNMPv2cCredential | SNMPv3Credential


class SNMPError(Exception):
    """Base exception for SNMP operations."""
    pass


class SNMPTimeoutError(SNMPError):
    """SNMP request timed out."""
    pass


class SNMPClient:
    """
    Unified SNMP client supporting v2c and v3.

    Usage:
        client = SNMPClient(host="192.168.1.1", port=161, timeout=5, retries=2)
        result = await client.get("1.3.6.1.2.1.1.1.0", SNMPv2cCredential("public"))
    """

    def __init__(
        self,
        host: str,
        port: int = 161,
        timeout: int = 5,
        retries: int = 2
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self._engine = SnmpEngine()

    def _get_auth_data(self, credential: SNMPCredential):
        """Build pysnmp auth data from credential."""
        if isinstance(credential, SNMPv2cCredential):
            return CommunityData(credential.community)

        # SNMPv3
        auth_proto = AUTH_PROTOCOL_MAP.get(credential.auth_protocol, usmNoAuthProtocol)
        priv_proto = PRIV_PROTOCOL_MAP.get(credential.priv_protocol, usmNoPrivProtocol)

        return UsmUserData(
            userName=credential.username,
            authKey=credential.auth_password,
            privKey=credential.priv_password,
            authProtocol=auth_proto,
            privProtocol=priv_proto,
        )

    async def _get_transport(self):
        """Build UDP transport target (async in pysnmp v6)."""
        return await UdpTransportTarget.create(
            (self.host, self.port),
            timeout=self.timeout,
            retries=self.retries
        )

    async def get(self, oid: str, credential: SNMPCredential) -> str | None:
        """
        Get a single OID value.

        Args:
            oid: The OID to retrieve
            credential: SNMP credential (v2c or v3)

        Returns:
            The OID value as string, or None if not found
        """
        transport = await self._get_transport()

        error_indication, error_status, error_index, var_binds = await get_cmd(
            self._engine,
            self._get_auth_data(credential),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )

        if error_indication:
            if "timeout" in str(error_indication).lower():
                raise SNMPTimeoutError(f"SNMP timeout for {self.host}: {error_indication}")
            raise SNMPError(f"SNMP error for {self.host}: {error_indication}")

        if error_status:
            raise SNMPError(
                f"SNMP error {error_status.prettyPrint()} at "
                f"{error_index and var_binds[int(error_index) - 1][0] or '?'}"
            )

        for var_bind in var_binds:
            oid_str, value = var_bind
            if value is None or str(value) == "":
                return None
            # Check for noSuchObject or noSuchInstance
            value_str = str(value)
            if "noSuch" in value_str:
                return None
            return value_str

        return None

    async def get_bulk(
        self,
        oids: list[str],
        credential: SNMPCredential
    ) -> dict[str, Any]:
        """
        Get multiple OIDs in a single request.

        Args:
            oids: List of OIDs to retrieve
            credential: SNMP credential (v2c or v3)

        Returns:
            Dict mapping OID to value
        """
        if not oids:
            return {}

        transport = await self._get_transport()
        object_types = [ObjectType(ObjectIdentity(oid)) for oid in oids]

        error_indication, error_status, error_index, var_binds = await get_cmd(
            self._engine,
            self._get_auth_data(credential),
            transport,
            ContextData(),
            *object_types
        )

        if error_indication:
            if "timeout" in str(error_indication).lower():
                raise SNMPTimeoutError(f"SNMP timeout for {self.host}: {error_indication}")
            raise SNMPError(f"SNMP error for {self.host}: {error_indication}")

        if error_status:
            raise SNMPError(
                f"SNMP error {error_status.prettyPrint()} at "
                f"{error_index and var_binds[int(error_index) - 1][0] or '?'}"
            )

        results = {}
        for var_bind in var_binds:
            oid_str = str(var_bind[0])
            value = var_bind[1]
            if value is not None and "noSuch" not in str(value):
                results[oid_str] = str(value)

        return results

    async def walk(
        self,
        oid: str,
        credential: SNMPCredential,
        max_rows: int | None = None
    ) -> list[tuple[str, Any]]:
        """
        Walk an OID tree using GETBULK, with automatic fallback to GETNEXT.

        Tries GETBULK first for performance. If the device doesn't support it
        (returns error or empty results), automatically falls back to GETNEXT.

        Args:
            oid: The base OID to walk
            credential: SNMP credential (v2c or v3)
            max_rows: Maximum number of rows to retrieve (None = unlimited)

        Returns:
            List of (oid, value) tuples
        """
        try:
            results = await self._bulk_walk(oid, credential, max_rows)
            # If bulk walk returns empty but we expected data, try getnext
            if not results:
                return await self._getnext_walk(oid, credential, max_rows)
            return results
        except SNMPError as e:
            # If GETBULK fails (some devices don't support it), fall back to GETNEXT
            if "tooBig" in str(e) or "genErr" in str(e):
                return await self._getnext_walk(oid, credential, max_rows)
            raise

    async def _bulk_walk(
        self,
        oid: str,
        credential: SNMPCredential,
        max_rows: int | None = None
    ) -> list[tuple[str, Any]]:
        """
        Walk an OID tree using GETBULK requests.
        Continues walking until the tree is exhausted or max_rows is reached.

        Args:
            oid: The base OID to walk
            credential: SNMP credential (v2c or v3)
            max_rows: Maximum number of rows to retrieve (None = unlimited)

        Returns:
            List of (oid, value) tuples
        """
        results = []
        base_oid = oid.rstrip(".")
        current_oid = oid
        batch_size = 50  # Number of rows per GETBULK request

        while True:
            transport = await self._get_transport()

            error_indication, error_status, error_index, var_binds = await bulk_cmd(
                self._engine,
                self._get_auth_data(credential),
                transport,
                ContextData(),
                0,  # nonRepeaters
                batch_size,  # maxRepetitions
                ObjectType(ObjectIdentity(current_oid))
            )

            if error_indication:
                if "timeout" in str(error_indication).lower():
                    raise SNMPTimeoutError(f"SNMP timeout for {self.host}: {error_indication}")
                raise SNMPError(f"SNMP error for {self.host}: {error_indication}")

            if error_status:
                raise SNMPError(
                    f"SNMP error {error_status.prettyPrint()} at "
                    f"{error_index and var_binds[int(error_index) - 1][0] or '?'}"
                )

            if not var_binds:
                break

            last_oid = None
            for var_bind in var_binds:
                oid_str = str(var_bind[0])
                value = var_bind[1]

                # Stop if we've walked past our base OID
                if not oid_str.startswith(base_oid):
                    return results

                # Skip endOfMib or noSuch values
                value_str = str(value) if value is not None else ""
                if "noSuch" in value_str or "endOfMib" in value_str:
                    return results

                results.append((oid_str, value_str))
                last_oid = oid_str

                # Check if we've hit max_rows
                if max_rows is not None and len(results) >= max_rows:
                    return results

            # If we got fewer results than batch_size, we're done
            if len(var_binds) < batch_size:
                break

            # Continue from the last OID
            if last_oid:
                current_oid = last_oid
            else:
                break

        return results

    async def _getnext_walk(
        self,
        oid: str,
        credential: SNMPCredential,
        max_rows: int | None = None
    ) -> list[tuple[str, Any]]:
        """
        Walk an OID tree using GETNEXT requests (slower but more compatible).

        Args:
            oid: The base OID to walk
            credential: SNMP credential (v2c or v3)
            max_rows: Maximum number of rows to retrieve (None = unlimited)

        Returns:
            List of (oid, value) tuples
        """
        from pysnmp.hlapi.v3arch.asyncio import next_cmd

        results = []
        base_oid = oid.rstrip(".")
        current_oid = oid

        while True:
            transport = await self._get_transport()

            error_indication, error_status, error_index, var_binds = await next_cmd(
                self._engine,
                self._get_auth_data(credential),
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(current_oid))
            )

            if error_indication:
                if "timeout" in str(error_indication).lower():
                    raise SNMPTimeoutError(f"SNMP timeout for {self.host}: {error_indication}")
                raise SNMPError(f"SNMP error for {self.host}: {error_indication}")

            if error_status:
                raise SNMPError(
                    f"SNMP error {error_status.prettyPrint()} at "
                    f"{error_index and var_binds[int(error_index) - 1][0] or '?'}"
                )

            if not var_binds:
                break

            var_bind = var_binds[0]
            oid_str = str(var_bind[0])
            value = var_bind[1]

            # Stop if we've walked past our base OID
            if not oid_str.startswith(base_oid):
                break

            # Skip endOfMib or noSuch values
            value_str = str(value) if value is not None else ""
            if "noSuch" in value_str or "endOfMib" in value_str:
                break

            results.append((oid_str, value_str))
            current_oid = oid_str

            # Check if we've hit max_rows
            if max_rows is not None and len(results) >= max_rows:
                break

        return results

    async def test_connection(self, credential: SNMPCredential) -> bool:
        """
        Test if SNMP connection works by querying sysDescr.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            result = await self.get("1.3.6.1.2.1.1.1.0", credential)
            return result is not None
        except SNMPError:
            return False
