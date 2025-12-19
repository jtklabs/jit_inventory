"""
Credential management module.
"""
from src.config.settings import get_settings
from src.credentials.base import CredentialProvider
from src.credentials.local import LocalCredentialProvider


def get_credential_provider() -> CredentialProvider:
    """Get the configured credential provider."""
    settings = get_settings()

    if settings.credential_backend == "aws":
        from src.credentials.aws_secrets import AWSSecretsProvider

        return AWSSecretsProvider()

    return LocalCredentialProvider(settings.credential_path)
