from __future__ import annotations
import typing
import uuid

from .models import SecretRecord


# SDK rebuild AAD and the KMS context at read time.
# Go writer and the Python reader must produce byte-for-byte
# identical AAD and an exactly matching EncryptionContext.
def make_aad_and_enc_ctx(
    tenant_id: uuid.UUID, key: str
) -> typing.Tuple[bytes, typing.Dict[str, str]]:
    aad = f"tenant:{tenant_id}|key:{key}".encode("utf-8")
    enc_ctx = {"tenant_id": str(tenant_id), "key": key}
    return aad, enc_ctx


def aad_and_enc_ctx_from_record(
    rec: SecretRecord,
) -> typing.Tuple[bytes, typing.Dict[str, str]]:
    return make_aad_and_enc_ctx(rec.tenant_id, rec.key)


AADEncCtxBuilder = typing.Callable[
    [SecretRecord], typing.Tuple[bytes, typing.Dict[str, str]]
]
