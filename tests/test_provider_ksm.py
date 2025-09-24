import base64
import json
import pytest

from vault.providers.kms import KMSProvider


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


class FakeBoto3KMS:
    """Minimal fake KMS client that records decrypt calls and returns a fixed plaintext."""

    def __init__(self, plaintext: bytes = b"PLAINTEXT-DEK"):
        self.plaintext = plaintext
        self.calls = []

    def decrypt(self, **kwargs):
        # Record the exact kwargs for assertions
        self.calls.append(kwargs)
        return {"Plaintext": self.plaintext}


def test_decrypt_caches_and_passthrough_params():
    fake = FakeBoto3KMS(b"DEK-1")
    p = KMSProvider(boto3_kms_client=fake, cache_ttl_seconds=300, cache_maxsize=16)

    wrapped = b64e(b"WRAPPED-DEK")
    enc_ctx_a = {"tenant_id": "t-123", "key": "apps/backend/db_password"}
    # same data, different key ordering (should hit cache)
    enc_ctx_a_shuffled = {"key": "apps/backend/db_password", "tenant_id": "t-123"}
    key_id = "alias/dsvault-kek"

    # 1st call → hits KMS
    out1 = p.decrypt_dek(
        wrapped_dek_b64=wrapped,
        encryption_context=enc_ctx_a,
        key_id=key_id,
    )
    assert out1 == b"DEK-1"
    assert len(fake.calls) == 1
    # Params passed to KMS as expected
    call = fake.calls[0]
    assert call["CiphertextBlob"] == b"WRAPPED-DEK"
    assert call["EncryptionContext"] == enc_ctx_a
    assert call["KeyId"] == key_id

    # 2nd call (same inputs) → cache hit, no new KMS call
    out2 = p.decrypt_dek(
        wrapped_dek_b64=wrapped,
        encryption_context=enc_ctx_a,
        key_id=key_id,
    )
    assert out2 == b"DEK-1"
    assert len(fake.calls) == 1  # still one call

    # 3rd call (same inputs but shuffled enc_ctx order) → still cache hit
    out3 = p.decrypt_dek(
        wrapped_dek_b64=wrapped,
        encryption_context=enc_ctx_a_shuffled,
        key_id=key_id,
    )
    assert out3 == b"DEK-1"
    assert len(fake.calls) == 1

    # 4th call (bypass_cache=True) → must hit KMS again
    out4 = p.decrypt_dek(
        wrapped_dek_b64=wrapped,
        encryption_context=enc_ctx_a,
        key_id=key_id,
        bypass_cache=True,
    )
    assert out4 == b"DEK-1"
    assert len(fake.calls) == 2

    # 5th call (different key_id) → different cache key → hits KMS
    out5 = p.decrypt_dek(
        wrapped_dek_b64=wrapped,
        encryption_context=enc_ctx_a,
        key_id="alias/other",
    )
    assert out5 == b"DEK-1"
    assert len(fake.calls) == 3

    # 6th call (different enc ctx value) → different cache key → hits KMS
    out6 = p.decrypt_dek(
        wrapped_dek_b64=wrapped,
        encryption_context={"tenant_id": "t-123", "key": "apps/backend/OTHER"},
        key_id=key_id,
    )
    assert out6 == b"DEK-1"
    assert len(fake.calls) == 4


def test_cache_key_is_order_invariant_and_none_safe():
    fake = FakeBoto3KMS()
    p = KMSProvider(boto3_kms_client=fake)

    wrapped = b64e(b"W")
    ctx1 = {"a": "1", "b": "2"}
    ctx2 = {"b": "2", "a": "1"}

    k1 = p._cache_key(wrapped, ctx1, "kid")
    k2 = p._cache_key(wrapped, ctx2, "kid")
    assert k1 == k2  # sorted JSON makes order invariant

    k3 = p._cache_key(wrapped, None, None)
    # should serialize to an empty JSON object for the enc ctx portion
    assert k3[1] == json.dumps({}, sort_keys=True, separators=(",", ":"))
    assert k3[2] == ""  # empty key_id becomes empty string


def test_invalid_base64_raises_and_does_not_call_kms():
    fake = FakeBoto3KMS()
    p = KMSProvider(boto3_kms_client=fake)

    with pytest.raises(Exception):
        p.decrypt_dek(wrapped_dek_b64="***not-base64***")

    # ensure KMS wasn't called at all
    assert fake.calls == []
