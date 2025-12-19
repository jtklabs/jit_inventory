"""
Abstract base class for credential providers.
"""
from abc import ABC, abstractmethod

from src.credentials.models import CredentialProfile


class CredentialProvider(ABC):
    """Abstract interface for credential storage providers."""

    @abstractmethod
    async def list_profiles(self) -> list[str]:
        """List all credential profile names sorted by priority."""
        pass

    @abstractmethod
    async def get_profile(self, name: str) -> CredentialProfile | None:
        """Get a credential profile by name."""
        pass

    @abstractmethod
    async def get_all_profiles_ordered(self) -> list[CredentialProfile]:
        """Get all profiles ordered by priority (lowest first)."""
        pass

    @abstractmethod
    async def save_profile(self, profile: CredentialProfile) -> None:
        """Save or update a credential profile."""
        pass

    @abstractmethod
    async def delete_profile(self, name: str) -> None:
        """Delete a credential profile."""
        pass

    @abstractmethod
    async def profile_exists(self, name: str) -> bool:
        """Check if a profile exists."""
        pass

    @abstractmethod
    async def update_priority(self, name: str, priority: int) -> None:
        """Update the priority of a profile."""
        pass
