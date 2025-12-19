"""
Local file-based credential storage for development.
Credentials stored encrypted in data/credentials/ directory.
"""
import json
from pathlib import Path

from cryptography.fernet import Fernet

from src.credentials.base import CredentialProvider
from src.credentials.models import CredentialProfile, profile_from_dict


class LocalCredentialProvider(CredentialProvider):
    """
    Stores credentials in encrypted JSON files locally.

    Structure:
    data/credentials/
    ├── .key              # Encryption key (gitignored)
    └── profiles.json.enc # Encrypted credential profiles
    """

    def __init__(self, base_path: str = "data/credentials"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._key_file = self.base_path / ".key"
        self._profiles_file = self.base_path / "profiles.json.enc"
        self._fernet: Fernet | None = None

    def _get_fernet(self) -> Fernet:
        """Get or create Fernet encryption instance."""
        if self._fernet is None:
            if self._key_file.exists():
                key = self._key_file.read_bytes()
            else:
                key = Fernet.generate_key()
                self._key_file.write_bytes(key)
            self._fernet = Fernet(key)
        return self._fernet

    def _load_profiles(self) -> dict:
        """Load and decrypt profiles from file."""
        if not self._profiles_file.exists():
            return {}
        try:
            encrypted = self._profiles_file.read_bytes()
            decrypted = self._get_fernet().decrypt(encrypted)
            return json.loads(decrypted)
        except Exception:
            return {}

    def _save_profiles(self, profiles: dict) -> None:
        """Encrypt and save profiles to file."""
        data = json.dumps(profiles, indent=2).encode()
        encrypted = self._get_fernet().encrypt(data)
        self._profiles_file.write_bytes(encrypted)

    async def list_profiles(self) -> list[str]:
        """List all credential profile names sorted by priority."""
        profiles = self._load_profiles()
        # Sort by priority (lower first), then by name
        sorted_names = sorted(
            profiles.keys(),
            key=lambda n: (profiles[n].get("priority", 100), n)
        )
        return sorted_names

    async def get_profile(self, name: str) -> CredentialProfile | None:
        """Get a credential profile by name."""
        profiles = self._load_profiles()
        data = profiles.get(name)
        if not data:
            return None

        return profile_from_dict(data)

    async def get_all_profiles_ordered(self) -> list[CredentialProfile]:
        """Get all profiles ordered by priority (lowest first)."""
        profiles = self._load_profiles()
        # Sort by priority, then by name
        sorted_items = sorted(
            profiles.items(),
            key=lambda item: (item[1].get("priority", 100), item[0])
        )
        return [profile_from_dict(data) for _, data in sorted_items]

    async def update_priority(self, name: str, priority: int) -> None:
        """Update the priority of a profile."""
        profiles = self._load_profiles()
        if name in profiles:
            profiles[name]["priority"] = priority
            self._save_profiles(profiles)

    async def save_profile(self, profile: CredentialProfile) -> None:
        """Save or update a credential profile."""
        profiles = self._load_profiles()

        # Serialize profile to dict, handling SecretStr
        profile_dict = profile.model_dump()
        # Convert SecretStr to actual string values for storage
        if "community" in profile_dict and hasattr(profile.community, "get_secret_value"):
            profile_dict["community"] = profile.community.get_secret_value()
        if "auth_password" in profile_dict and profile.auth_password:
            profile_dict["auth_password"] = profile.auth_password.get_secret_value()
        if "priv_password" in profile_dict and profile.priv_password:
            profile_dict["priv_password"] = profile.priv_password.get_secret_value()

        # Convert enum values to strings
        if "auth_protocol" in profile_dict and profile_dict["auth_protocol"]:
            profile_dict["auth_protocol"] = profile_dict["auth_protocol"].value if hasattr(profile_dict["auth_protocol"], "value") else profile_dict["auth_protocol"]
        if "priv_protocol" in profile_dict and profile_dict["priv_protocol"]:
            profile_dict["priv_protocol"] = profile_dict["priv_protocol"].value if hasattr(profile_dict["priv_protocol"], "value") else profile_dict["priv_protocol"]

        profiles[profile.name] = profile_dict
        self._save_profiles(profiles)

    async def delete_profile(self, name: str) -> None:
        """Delete a credential profile."""
        profiles = self._load_profiles()
        profiles.pop(name, None)
        self._save_profiles(profiles)

    async def profile_exists(self, name: str) -> bool:
        """Check if a profile exists."""
        profiles = self._load_profiles()
        return name in profiles
