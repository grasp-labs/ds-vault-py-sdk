import base64
from unittest import TestCase
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest

from vault.crypto import make_aad_and_enc_ctx
from vault.keys import make_key
from vault.providers.kms import KMSProvider
from vault import DSVaultClient, SecretRecord, SecretNotFound
from vault.repositories.memory import InMemorySecretRepository


def test_ds_vault_get_secret_round_trip():
    """
    Unittest, making use use of Fake KMS provider, simulating
    the storing of a secret, encrypted by DEK, wrapped by KEK,
    before fetching and decoding secret.

    Four paramenters has to be set, that is used in
    creating and encrypting/decrypting secret (aad and encryption 
    context).
    """
    secret_id = uuid.uuid4()
    tenant_id = uuid.uuid4()
    store = "ds_vault"
    environment = os.environ.get("BUILDING_MODE", "dev")
    
    plaintext = b"super-secret-value"
    b64bytes = base64.b64encode(plaintext)
    dek = os.urandom(32) # 256-bit AES key
    aesgcm = AESGCM(dek)
    key = make_key(secret_id, tenant_id, store, environment)
    aad, enc_ctx = make_aad_and_enc_ctx(tenant_id, key)
    
    # First connect to database and fetch record
    repository = 
    client = DSVaultClient()

    # Unwrap and decrypt
    decrypted_dek = KMSProvider().decrypt_dek(
        dek_encrypted_b64,
        encryption_context,
    )