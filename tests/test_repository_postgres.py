import datetime as dt
import os
import sqlite3
import uuid

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vault.repositories.postgres import PostgresSecretRepository
from vault import DSVaultClient, SecretNotFound
from vault.aad import make_aad_and_enc_ctx
from vault.keys import make_key
from vault.models import Status

from .helpers import b64e, create_sqlite_table, FakeKMS


def test_postgres_repo_sqlite_mock_e2e_unwrap_and_decrypt(
    sqlite_mem_dsn, keepalive_conn
):
    # table name has hex ending to avoid collisions
    table = f"secrets_{uuid.uuid4().hex[:8]}"
    # keep connection alive
    create_sqlite_table(keepalive_conn, table)

    # --- Arrange payload ---
    tenant_id = uuid.uuid4()
    secret_id = uuid.uuid4()
    now = dt.datetime.now(dt.timezone.utc)
    kek_key_id = "arn:aws:kms:eu-north-1:123456789012:key/abcd-ef"
    store = "ds_vault"
    environment = "dev"

    dek = os.urandom(32)
    iv = os.urandom(12)
    key = make_key(secret_id, tenant_id, store, environment)
    aad, enc_ctx = make_aad_and_enc_ctx(tenant_id, key)

    aesgcm = AESGCM(dek)
    pt = b"p@ssw0rd"
    ct_with_tag = aesgcm.encrypt(iv, pt, aad)
    value_b64 = b64e(ct_with_tag[:-16])
    tag_b64 = b64e(ct_with_tag[-16:])
    iv_b64 = b64e(iv)
    wrapped_dek_b64 = b64e(b"WRAPPED:" + dek)

    # Insert row via SQLite
    conn = sqlite3.connect(sqlite_mem_dsn, uri=True, check_same_thread=False)
    try:
        cur = conn.cursor()
        cur.execute(
            f"""
            INSERT INTO {table} (
              id, tenant_id, owner_id, issuer, name, version, description, status,
              metadata, tags, created_at, created_by, modified_at, modified_by,
              key, store, value, acl, iv, tag, wrapped_dek, kek_key_id, dek_alg, wrap_alg
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,  # noqa
            (
                str(secret_id),
                str(tenant_id),
                None,
                "issuer-x",
                "db_password",
                "v3",
                "postgres password",
                Status.ACTIVE.value,
                None,  # metadata
                None,  # tags
                now.isoformat(),
                "svc:seeder",
                now.isoformat(),
                "svc:seeder",
                key,
                "ds_vault",
                value_b64,
                None,  # acl
                iv_b64,
                tag_b64,
                wrapped_dek_b64,
                kek_key_id,
                "AES256-GCM",
                "AWS-KMS",
            ),
        )
        conn.commit()
    finally:
        conn.close()

    # --- Act via the real repository & client (but DB is SQLite) ---
    repo = PostgresSecretRepository(dsn=sqlite_mem_dsn, table=table)
    kms = FakeKMS(dek=dek, expect_ctx=enc_ctx, expect_key_id=kek_key_id)
    client = DSVaultClient(repository=repo, kms_provider=kms)

    out = client.get_secret(key=key)

    # --- Assert ---
    assert out == pt


def test_postgres_repo_sqlite_mock_not_found(sqlite_mem_dsn, keepalive_conn):
    table = f"secrets_{uuid.uuid4().hex[:8]}"
    create_sqlite_table(keepalive_conn, table)

    repo = PostgresSecretRepository(dsn=sqlite_mem_dsn, table=table)
    kms = FakeKMS(os.urandom(32), {"tenant_id": "x", "key": "y"}, None)
    client = DSVaultClient(repository=repo, kms_provider=kms)

    key = make_key(uuid.uuid4(), uuid.uuid4(), "ds_vault", "environment")
    with pytest.raises(SecretNotFound):
        client.get_secret(key=key)
