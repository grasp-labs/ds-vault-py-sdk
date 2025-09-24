from __future__ import annotations
import boto3
from ..cache import TTLCache


class SSMProvider:
    """
    Thin wrapper around AWS SSM Parameter Store with a small TTL cache.
    If parameter_prefix is set, it is prepended to names (e.g., "/prod/app").
    """

    def __init__(
        self,
        *,
        boto3_ssm_client=None,
        cache_ttl_seconds: int = 300,
        cache_maxsize: int = 1024,
    ) -> None:
        self._ssm = boto3_ssm_client or boto3.client("ssm")
        self._cache = TTLCache(maxsize=cache_maxsize, ttl_seconds=cache_ttl_seconds)

    def get_parameter_value(self, key: str, *, bypass_cache: bool = False) -> bytes:
        if not bypass_cache:
            cached = self._cache.get(key)
            if cached is not None:
                return cached

        out = self._ssm.get_parameter(Name=key, WithDecryption=True)
        val = out["Parameter"]["Value"]
        b = val.encode("utf-8") if isinstance(val, str) else bytes(val)
        self._cache.set(key, b)
        return b
