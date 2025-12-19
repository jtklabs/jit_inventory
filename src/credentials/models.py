"""
Credential data models using Pydantic.
"""
from typing import Literal

from pydantic import BaseModel, SecretStr

from src.snmp.client import (
    AuthProtocol,
    PrivProtocol,
    SNMPv2cCredential,
    SNMPv3Credential,
)


class SNMPv2cProfile(BaseModel):
    """SNMPv2c credential profile."""

    name: str
    version: Literal["v2c"] = "v2c"
    community: SecretStr
    description: str | None = None
    priority: int = 100  # Lower = tried first during auto-discovery

    def to_snmp_credential(self) -> SNMPv2cCredential:
        """Convert to SNMP client credential."""
        return SNMPv2cCredential(community=self.community.get_secret_value())


class SNMPv3Profile(BaseModel):
    """SNMPv3 credential profile."""

    name: str
    version: Literal["v3"] = "v3"
    username: str
    auth_protocol: AuthProtocol | None = None
    auth_password: SecretStr | None = None
    priv_protocol: PrivProtocol | None = None
    priv_password: SecretStr | None = None
    description: str | None = None
    priority: int = 100  # Lower = tried first during auto-discovery

    @property
    def security_level(self) -> str:
        """Return the security level based on configured protocols."""
        if self.priv_protocol and self.auth_protocol:
            return "authPriv"
        elif self.auth_protocol:
            return "authNoPriv"
        return "noAuthNoPriv"

    def to_snmp_credential(self) -> SNMPv3Credential:
        """Convert to SNMP client credential."""
        return SNMPv3Credential(
            username=self.username,
            auth_protocol=self.auth_protocol or AuthProtocol.NONE,
            auth_password=(
                self.auth_password.get_secret_value() if self.auth_password else None
            ),
            priv_protocol=self.priv_protocol or PrivProtocol.NONE,
            priv_password=(
                self.priv_password.get_secret_value() if self.priv_password else None
            ),
        )


CredentialProfile = SNMPv2cProfile | SNMPv3Profile


def profile_from_dict(data: dict) -> CredentialProfile:
    """Create a credential profile from a dictionary."""
    version = data.get("version", "v2c")
    if version == "v2c":
        return SNMPv2cProfile(**data)
    return SNMPv3Profile(**data)
