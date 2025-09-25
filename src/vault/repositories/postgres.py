from __future__ import annotations
import typing
import re

from .base import SecretRepository
from ..cache import TTLCache
from ..models import SecretRecord, Status


try:
    import psycopg  # type: ignore

    try:
        from psycopg.rows import tuple_row  # optional nicety
    except Exception:
        tuple_row = None  # fallback if rows module missing
    _HAS_PG = True
except ImportError:
    psycopg = None  # type: ignore
    tuple_row = None
    _HAS_PG = False


_VALID_TABLE = re.compile(r"^[A-Za-z0-9_\.]+$")


def _validate_table_name(table: str) -> str:
    if not _VALID_TABLE.match(table):
        raise ValueError("Invalid table name (letters/digits/_/.)")
    return table


class PostgresSecretRepository(SecretRepository):
    """
    Expects a table with columns matching SecretRecord names.
    """

    def __init__(
        self,
        dsn: str,
        *,
        table: str = "secrets",
        cache_ttl_seconds: int = 60,
        cache_maxsize: int = 4096,
    ) -> None:
        self._dsn = dsn
        self._table = _validate_table_name(table)
        self._cache = TTLCache(maxsize=cache_maxsize, ttl_seconds=cache_ttl_seconds)

    def _row_to_model(self, row: typing.Tuple[typing.Any, ...]) -> SecretRecord:
        (
            id,
            tenant_id,
            owner_id,
            issuer,
            name,
            version,
            description,
            status,
            metadata,
            tags,
            created_at,
            created_by,
            modified_at,
            modified_by,
            key,
            store,
            value,
            acl,
            iv,
            tag,
            wrapped_dek,
            kek_key_id,
            dek_alg,
            wrap_alg,
        ) = row

        return SecretRecord(
            id=id,
            tenant_id=tenant_id,
            owner_id=owner_id,
            issuer=issuer,
            name=name,
            version=version,
            description=description,
            status=Status(status) if not isinstance(status, Status) else status,
            metadata=metadata or {},
            tags=tags or {},
            created_at=created_at,
            created_by=created_by,
            modified_at=modified_at,
            modified_by=modified_by,
            key=key,
            store=store,
            value=value,
            acl=acl or {},
            iv=iv,
            tag=tag,
            wrapped_dek=wrapped_dek,
            kek_key_id=kek_key_id,
            dek_alg=dek_alg,
            wrap_alg=wrap_alg,
        )

    def get_secret_record(self, *, key: str) -> typing.Optional[SecretRecord]:
        if not _HAS_PG:
            raise ImportError(
                "psycopg3 is not installed. Install the Postgres extra:\n"
                "  pip install 'ds-vault-py-sdk[postgres]'"
            )
        # Cache by the exact lookup key string
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        sql = (
            f"SELECT id, tenant_id, owner_id, issuer, name, version, description, status, "
            f"metadata, tags, created_at, created_by, modified_at, modified_by, "
            f"key, store, value, acl, iv, tag, wrapped_dek, kek_key_id, dek_alg, wrap_alg "
            f"FROM {self._table} WHERE key = %s LIMIT 1"
        )

        with psycopg.connect(self._dsn, autocommit=True, row_factory=tuple_row) as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (key,))
                row = cur.fetchone()
                if not row:
                    return None

                rec = self._row_to_model(row)
                self._cache.set(key, rec)
                return rec
