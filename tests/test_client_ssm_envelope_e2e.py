import datetime as dt
import uuid
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vault.repositories.postgres import PostgresSecretRepository
from vault import DSVaultClient
from vault.models import Status
from vault.keys import make_key
from vault.aad import make_aad_and_enc_ctx
from vault.providers.ssm import SSMProvider

from .helpers import b64e, create_sqlite_table, FakeKMS, FakeSSM


def test_record_in_db_cipher_in_ssm_envelope(sqlite_mem_dsn, keepalive_conn):
    table = f"secrets_{uuid.uuid4().hex[:8]}"
    create_sqlite_table(keepalive_conn, table)

    tenant_id = uuid.uuid4()
    secret_id = uuid.uuid4()
    env = "dev"
    store = "aws_ssm"
    now = dt.datetime.now(dt.timezone.utc)

    # This is both the SecretRecord.key and the SSM parameter name
    lookup_key = make_key(secret_id, tenant_id, store, env)

    # --- Prepare envelope materials
    dek = os.urandom(32)  # plaintext DEK
    iv = os.urandom(12)
    aad, enc_ctx = make_aad_and_enc_ctx(tenant_id, lookup_key)
    aesgcm = AESGCM(dek)
    plaintext = b"p@ssw0rd"
    ct_with_tag = aesgcm.encrypt(iv, plaintext, aad)
    value_b64 = b64e(ct_with_tag[:-16])  # ciphertext (NO tag)
    tag_b64 = b64e(ct_with_tag[-16:])  # tag
    iv_b64 = b64e(iv)
    wrapped_dek_b64 = b64e(b"WRAPPED:" + dek)
    kek_key_id = "arn:aws:kms:eu-north-1:123456789012:key/abcd-ef"

    # --- Insert the record in DB (cipher fields present except value)
    cur = keepalive_conn.cursor()
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
            "desc",
            Status.ACTIVE.value,
            None,
            None,
            now.isoformat(),
            "svc",
            now.isoformat(),
            "svc",
            lookup_key,
            store,
            "",
            None,
            iv_b64,
            tag_b64,
            wrapped_dek_b64,
            kek_key_id,
            "AES256-GCM",
            "AWS-KMS",
        ),
    )
    keepalive_conn.commit()

    # --- Wire repo + providers + client
    repo = PostgresSecretRepository(dsn=sqlite_mem_dsn, table=table)
    ssm = SSMProvider(boto3_ssm_client=FakeSSM(value_b64))
    kms = FakeKMS(dek=dek, expect_ctx=enc_ctx, expect_key_id=kek_key_id)

    client = DSVaultClient(repository=repo, ssm_provider=ssm, kms_provider=kms)

    # Act: should fetch ciphertext from SSM and decrypt using DB metadata + KMS unwrap
    out1 = client.get_secret(key=lookup_key)
    assert out1 == plaintext
    assert kms.calls == 1

    # Cached plaintext (no extra KMS or SSM hit in client cache)
    out2 = client.get_secret(key=lookup_key)
    assert out2 == plaintext
