from __future__ import annotations
import base64
import typing

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def decrypt_aes_gcm_bytes(
    *,
    dek: bytes,
    value_b64: str,
    iv_b64: str,
    tag_b64: str,
    aad: typing.Optional[bytes],
) -> bytes:
    aesgcm = AESGCM(dek)
    iv = b64d(iv_b64)
    ct = b64d(value_b64)
    tag = b64d(tag_b64)
    ct_with_tag = ct + tag
    return aesgcm.decrypt(iv, ct_with_tag, aad)
