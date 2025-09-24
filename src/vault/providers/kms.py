from __future__ import annotations
import base64
import json
import typing

import boto3

from ..cache import TTLCache


class KMSProvider:
    def __init__(
        self,
        *,
        boto3_kms_client=None,
        cache_ttl_seconds: int = 300,
        cache_maxsize: int = 1024,
    ):
        self._kms = boto3_kms_client or boto3.client("kms")
        self._cache = TTLCache(maxsize=cache_maxsize, ttl_seconds=cache_ttl_seconds)

    def _cache_key(
        self,
        wrapped_dek_b64: str,
        encryption_context: typing.Optional[typing.Mapping[str, str]],
        key_id: typing.Optional[str],
    ) -> typing.Tuple[str, str, str]:
        enc_ctx_json = json.dumps(
            dict(encryption_context or {}), sort_keys=True, separators=(",", ":")
        )
        return (wrapped_dek_b64, enc_ctx_json, key_id or "")

    def decrypt_dek(
        self,
        *,
        wrapped_dek_b64: str,
        encryption_context: typing.Optional[typing.Mapping[str, str]] = None,
        key_id: typing.Optional[str] = None,
        bypass_cache: bool = False,
    ) -> bytes:
        ck = self._cache_key(wrapped_dek_b64, encryption_context, key_id)
        if not bypass_cache:
            cached = self._cache.get(ck)
            if cached is not None:
                return cached

        blob = base64.b64decode(wrapped_dek_b64)
        params = {"CiphertextBlob": blob}
        if encryption_context:
            params["EncryptionContext"] = dict(encryption_context)
        if key_id:
            params["KeyId"] = key_id

        out = self._kms.decrypt(**params)
        pt = out["Plaintext"]
        self._cache.set(ck, pt)
        return pt
