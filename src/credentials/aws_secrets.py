"""
AWS Secrets Manager credential storage for production.
"""
import json

import boto3
from botocore.exceptions import ClientError

from src.config.settings import get_settings
from src.credentials.base import CredentialProvider
from src.credentials.models import CredentialProfile, profile_from_dict


class AWSSecretsProvider(CredentialProvider):
    """
    Stores credentials in AWS Secrets Manager.

    Secret naming convention:
    - {prefix}snmp/profiles        # List of profile names
    - {prefix}snmp/credentials/{name}  # Individual credential secrets
    """

    def __init__(self, region: str | None = None, prefix: str | None = None):
        settings = get_settings()
        self.region = region or settings.aws_region
        self.prefix = prefix or settings.aws_secret_prefix
        self._client = None

    @property
    def client(self):
        """Lazy-load boto3 client."""
        if self._client is None:
            self._client = boto3.client("secretsmanager", region_name=self.region)
        return self._client

    def _secret_name(self, profile_name: str) -> str:
        """Get full secret name for a profile."""
        return f"{self.prefix}snmp/credentials/{profile_name}"

    def _index_secret_name(self) -> str:
        """Get secret name for profile index."""
        return f"{self.prefix}snmp/profiles"

    async def list_profiles(self) -> list[str]:
        """List all credential profile names."""
        try:
            response = self.client.get_secret_value(SecretId=self._index_secret_name())
            data = json.loads(response["SecretString"])
            return data.get("profiles", [])
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return []
            raise

    async def get_profile(self, name: str) -> CredentialProfile | None:
        """Get a credential profile by name."""
        try:
            response = self.client.get_secret_value(SecretId=self._secret_name(name))
            data = json.loads(response["SecretString"])
            return profile_from_dict(data)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            raise

    async def save_profile(self, profile: CredentialProfile) -> None:
        """Save or update a credential profile."""
        secret_name = self._secret_name(profile.name)

        # Serialize profile
        profile_dict = profile.model_dump()
        if "community" in profile_dict and hasattr(profile.community, "get_secret_value"):
            profile_dict["community"] = profile.community.get_secret_value()
        if "auth_password" in profile_dict and profile.auth_password:
            profile_dict["auth_password"] = profile.auth_password.get_secret_value()
        if "priv_password" in profile_dict and profile.priv_password:
            profile_dict["priv_password"] = profile.priv_password.get_secret_value()

        secret_value = json.dumps(profile_dict)

        try:
            self.client.update_secret(SecretId=secret_name, SecretString=secret_value)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                self.client.create_secret(
                    Name=secret_name,
                    SecretString=secret_value,
                    Description=f"SNMP credential profile: {profile.name}",
                )
            else:
                raise

        # Update index
        await self._update_index(profile.name, add=True)

    async def delete_profile(self, name: str) -> None:
        """Delete a credential profile."""
        try:
            self.client.delete_secret(
                SecretId=self._secret_name(name), ForceDeleteWithoutRecovery=True
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

        # Update index
        await self._update_index(name, add=False)

    async def profile_exists(self, name: str) -> bool:
        """Check if a profile exists."""
        profiles = await self.list_profiles()
        return name in profiles

    async def _update_index(self, profile_name: str, add: bool = True) -> None:
        """Update the profile index in Secrets Manager."""
        index_secret = self._index_secret_name()

        try:
            response = self.client.get_secret_value(SecretId=index_secret)
            data = json.loads(response["SecretString"])
            profiles = set(data.get("profiles", []))
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                profiles = set()
            else:
                raise

        if add:
            profiles.add(profile_name)
        else:
            profiles.discard(profile_name)

        index_data = json.dumps({"profiles": sorted(profiles)})

        try:
            self.client.update_secret(SecretId=index_secret, SecretString=index_data)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                self.client.create_secret(
                    Name=index_secret,
                    SecretString=index_data,
                    Description="SNMP credential profile index",
                )
            else:
                raise
