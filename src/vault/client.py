from __future__ import annotations
from typing import Optional, Mapping

from .aad import aad_and_enc_ctx_from_record, AADEncCtxBuilder
from .cache import TTLCache
from .crypto import decrypt_aes_gcm_bytes
from .exceptions import SecretNotFound, DecryptionFailed
from .providers.kms import KMSProvider
from .providers.ssm import SSMProvider
from .repositories.base import SecretRepository


class DSVaultClient:
    def __init__(
        self,
        *,
        repository: SecretRepository,
        kms_provider: Optional[KMSProvider] = None,
        ssm_provider: Optional[SSMProvider] = None,
        encryption_context_defaults: Optional[Mapping[str, str]] = None,
        aad_enc_ctx_builder: Optional[AADEncCtxBuilder] = None,
        plaintext_cache_ttl_seconds: int = 60,
        plaintext_cache_maxsize: int = 4096,
    ) -> None:
        self._repo = repository
        self._kms = kms_provider or KMSProvider()
        self._ssm = ssm_provider or SSMProvider()
        self._enc_ctx_defaults = dict(encryption_context_defaults or {})
        self._aad_enc_ctx_builder = aad_enc_ctx_builder or aad_and_enc_ctx_from_record
        self._pt_cache = TTLCache(plaintext_cache_maxsize, plaintext_cache_ttl_seconds)

    def get_secret(self, *, key: str, bypass_cache: bool = False) -> bytes:
        if not bypass_cache:
            cached = self._pt_cache.get(key)
            if cached is not None:
                return cached

        rec = self._repo.get_secret_record(key=key)
        if rec is None:
            raise SecretNotFound(f"Secret {key} not found")

        # Build AAD and EncCtx exactly like Go
        aad, enc_ctx_base = self._aad_enc_ctx_builder(rec)
        # Merge any defaults first, then overlay the required keys from the builder
        enc_ctx = {**self._enc_ctx_defaults, **enc_ctx_base}

        try:
            dek = self._kms.decrypt_dek(
                wrapped_dek_b64=rec.wrapped_dek,
                encryption_context=enc_ctx,
                key_id=rec.kek_key_id or None,
            )
        except Exception as e:
            raise DecryptionFailed(f"KMS Decrypt failed: {e}") from e

        # Get ciphertext source:
        # - DS Vault: ciphertext stored in DB (rec.value)
        # - AWS SSM: ciphertext stored in Parameter Store under rec.key
        if (rec.store or "").lower() == "aws_ssm":
            value_b64 = self._ssm.get_parameter_value(
                rec.key, bypass_cache=bypass_cache
            )
        else:
            value_b64 = rec.value

        try:
            pt = decrypt_aes_gcm_bytes(
                dek=dek,
                value_b64=value_b64,
                iv_b64=rec.iv,
                tag_b64=rec.tag,
                aad=aad,
            )
        except Exception as e:
            raise DecryptionFailed(f"AES-GCM decrypt failed: {e}") from e

        self._pt_cache.set(key, pt)
        return pt
