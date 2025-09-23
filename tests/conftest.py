import uuid

import pytest
import sqlite3

from .helpers import sqlite_psycopg_connect

@pytest.fixture(scope="function")
def sqlite_mem_dsn() -> str:
    # Unique shared in-memory DB per test
    return f"file:dsvault_pgmock_{uuid.uuid4().hex}?mode=memory&cache=shared"

@pytest.fixture(autouse=True)
def patch_psycopg_to_sqlite(monkeypatch):
    import vault.repositories.postgres as pg_repo_mod
    # patch the psycopg.connect the repo uses
    monkeypatch.setattr(pg_repo_mod.psycopg, "connect", sqlite_psycopg_connect)
    yield

@pytest.fixture(scope="function")
def keepalive_conn(sqlite_mem_dsn):
    """Keep one connection open so the shared in-memory DB persists during the test."""
    conn = sqlite3.connect(sqlite_mem_dsn, uri=True, check_same_thread=False)
    try:
        yield conn
    finally:
        conn.close()