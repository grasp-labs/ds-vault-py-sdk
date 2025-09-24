# tests/test_get_secret_with_aad.py
import datetime as dt
import os
import pytest
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vault import DSVaultClient, SecretRecord, SecretNotFound
from vault.aad import make_aad_and_enc_ctx
from vault.keys import make_key
from vault.models import Status
from vault.repositories.memory import InMemorySecretRepository

from .helpers import b64e, FakeKMS


def test_unwrap_and_decrypt_round_trip_compatible():
    tenant_id = uuid.uuid4()
    secret_id = uuid.uuid4()
    now = dt.datetime.now(dt.timezone.utc)
    store = "ds_vault"
    environment = "dev"

    key = make_key(secret_id, tenant_id, store, environment)
    dek = os.urandom(32)
    aesgcm = AESGCM(dek)
    iv = os.urandom(12)

    # Build record skeleton
    rec_kwargs = dict(
        id=secret_id,
        tenant_id=tenant_id,
        issuer="issuer-x",
        name="db_password",
        version="v3",
        status=Status.ACTIVE,
        created_at=now,
        created_by="user@dp.com",
        modified_at=now,
        modified_by="another@dp.com",
        key=key,
        store="ds_vault",
        value="",
        acl={"r": ["svc-a"], "rw": ["svc-b"]},
        iv=b64e(iv),
        tag="",
        wrapped_dek=b64e(b"WRAPPED:" + dek),
        kek_key_id="arn:aws:kms:eu-north-1:123456789012:key/abcd-ef",
        dek_alg="AES256-GCM",
        wrap_alg="AWS-KMS",
        description="postgres password",
        metadata={"env": "prod"},
        tags={"team": "platform"},
    )

    aad, enc_ctx = make_aad_and_enc_ctx(tenant_id, rec_kwargs["key"])
    ct_with_tag = aesgcm.encrypt(iv, b"p@ssw0rd", aad)
    rec_kwargs["value"] = b64e(ct_with_tag[:-16])
    rec_kwargs["tag"] = b64e(ct_with_tag[-16:])
    rec = SecretRecord(**rec_kwargs)

    # Initiate Memory repository with data
    repo = InMemorySecretRepository({key: rec})
    kms = FakeKMS(dek, enc_ctx, rec.kek_key_id)
    client = DSVaultClient(repository=repo, kms_provider=kms)

    out = client.get_secret(key=key)
    assert out == b"p@ssw0rd"


def test_get_secret_not_found():
    repo = InMemorySecretRepository()
    kms = FakeKMS(os.urandom(32), {"tenant_id": "t", "key": "k"}, None)
    client = DSVaultClient(repository=repo, kms_provider=kms)
    store = "ds_vault"
    environment = "dev"
    key = make_key(uuid.uuid4, uuid.uuid4, store, environment)
    with pytest.raises(SecretNotFound):
        client.get_secret(key=key)
