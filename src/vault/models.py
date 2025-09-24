# src/dsvault/models.py
from __future__ import annotations
from dataclasses import dataclass, field
import datetime as dt
from enum import Enum
from typing import Dict, Optional
from uuid import UUID


class Status(str, Enum):
    ACTIVE = "active"
    DELETED = "deleted"
    SUSPENDED = "suspended"
    REJECTED = "rejected"
    DRAFT = "draft"
    CLOSED = "closed"


class Store(str, Enum):
    AWS_SSM = "aws_ssm"
    DS_VAULT = "ds_vault"


class Environment(str, Enum):
    DEV = "dev"
    PROD = "prod"


@dataclass(frozen=True)
class SecretRecord:
    # Common (required first)
    id: UUID
    tenant_id: UUID
    issuer: str
    name: str
    version: str
    status: Status
    created_at: dt.datetime
    created_by: str
    modified_at: dt.datetime
    modified_by: str

    # Vault specific (required)
    key: str
    store: str  # keep as str to match DB, values like Store.DS_VAULT.value
    value: str  # base64 ciphertext (no tag)
    acl: Dict
    iv: str  # base64 12-byte nonce
    tag: str  # base64 16-byte GCM tag
    wrapped_dek: str  # base64 KMS-wrapped DEK (CiphertextBlob)
    kek_key_id: str  # KMS key id or alias (informational)
    dek_alg: str  # e.g., "AES-256-GCM"
    wrap_alg: str  # e.g., "aws-kms"

    # Optionals (with defaults after required)
    owner_id: Optional[str] = None
    description: Optional[str] = None
    metadata: Dict = field(default_factory=dict)
    tags: Dict = field(default_factory=dict)
