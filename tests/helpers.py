import base64
import datetime as dt
import uuid

import sqlite3


# -------- Utils -------- #
def b64e(b: bytes) -> str: return base64.b64encode(b).decode()

# -------- SQLITE -------- #

def sqlite_psycopg_connect(dsn: str, autocommit: bool = False, row_factory=None):
    """
    Drop-in replacement for psycopg.connect used by the repository.
    Accepts a SQLite URI like: file:dsvault_pgmock?mode=memory&cache=shared
    """
    conn = sqlite3.connect(dsn, uri=True, check_same_thread=False)
    # emulate autocommit
    conn.isolation_level = None if autocommit else ""
    return _SqliteConnWrapper(conn)


class _SqliteCursorWrapper:
    def __init__(self, cur):
        self._cur = cur

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self._cur.close()

    def execute(self, sql: str, params=()):
        # Convert psycopg "%s" placeholders to sqlite "?"
        q, i = [], 0
        while i < len(sql):
            if sql[i] == "%" and i + 1 < len(sql) and sql[i + 1] == "s":
                q.append("?"); i += 2
            else:
                q.append(sql[i]); i += 1
        sql3 = "".join(q)

        # 🔧 ADAPT PARAM TYPES FOR SQLITE
        def _adapt(p):
            if isinstance(p, uuid.UUID):                     # UUID -> str
                return str(p)
            if isinstance(p, (dt.datetime, dt.date, dt.time)):  # dt -> ISO
                return p.isoformat()
            if isinstance(p, (dict, list)):             # JSON-like -> text
                return json.dumps(p)
            return p

        new_params = tuple(_adapt(p) for p in params)
        return self._cur.execute(sql3, new_params)

    def fetchone(self):
        return self._cur.fetchone()


class _SqliteConnWrapper:
    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self._conn.close()

    def cursor(self):
        return _SqliteCursorWrapper(self._conn.cursor())


# -------- KMS -------- #

class FakeKMS:
    """Minimal test double for KMS that validates enc ctx & key id."""
    def __init__(self, dek: bytes, expect_ctx: dict[str, str], expect_key_id: str | None):
        self._dek = dek
        self._expect_ctx = expect_ctx
        self._expect_key_id = expect_key_id
        self.calls = 0

    def decrypt_dek(self, *, wrapped_dek_b64: str, encryption_context=None, key_id=None) -> bytes:
        self.calls += 1
        assert encryption_context == self._expect_ctx, f"enc ctx mismatch: {encryption_context} != {self._expect_ctx}"
        if self._expect_key_id:
            assert key_id == self._expect_key_id, f"key id mismatch: {key_id} != {self._expect_key_id}"
        base64.b64decode(wrapped_dek_b64)  # sanity check base64
        return self._dek


# -------- PSQL -------- #
def create_sqlite_table(conn: sqlite3.Connection, table: str):
    cur = conn.cursor()
    # Schema compatible with repository SELECT order. Use TEXT for simplicity.
    cur.execute(
        f"""
        CREATE TABLE {table} (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            owner_id TEXT NULL,
            issuer TEXT NOT NULL,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            description TEXT NULL,
            status TEXT NOT NULL,
            metadata TEXT NULL,
            tags TEXT NULL,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            modified_at TEXT NOT NULL,
            modified_by TEXT NOT NULL,
            key TEXT NOT NULL,
            store TEXT NOT NULL,
            value TEXT NOT NULL,
            acl TEXT NULL,
            iv TEXT NOT NULL,
            tag TEXT NOT NULL,
            wrapped_dek TEXT NOT NULL,
            kek_key_id TEXT NOT NULL,
            dek_alg TEXT NOT NULL,
            kek_alg TEXT NOT NULL
        )
        """
    )
    conn.commit()


# -------- SSM -------- #
class FakeSSM:
    """Returns the ciphertext (base64) stored in SSM under Name=key."""
    def __init__(self, value_b64: str):
        self.value_b64 = value_b64
        self.calls = []
    def get_parameter(self, **kwargs):
        self.calls.append(kwargs)
        return {"Parameter": {"Value": self.value_b64}}


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()
