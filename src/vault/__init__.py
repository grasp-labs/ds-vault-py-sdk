"""
Public API surface
"""
from .client import DSVaultClient
from .exceptions import SecretNotFound, DecryptionFailed
from .models import SecretRecord


__all__ = ["DSVaultClient", "SecretNotFound", "DecryptionFailed", "SecretRecord"]
