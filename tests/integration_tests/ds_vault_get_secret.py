import os

from vault import DSVaultClient
from vault.repositories.postgres import PostgresSecretRepository


BUILDING_MODE = os.environ.get("BUILDING_MODE")


def ds_vault_get_secret_round_trip():
    """
    Integration Test, making use of `key` loaded from environment,
    in querying store `ds_vault` for secret to be returned in plaintext.

    `require` key to be stored prior to the execution of test.

    Test target DS Vault ´development´ environment.
    """

    is_dev = os.environ.get("BUILDING_MODE")
    if is_dev != "dev":
        raise ValueError("integration test should not be run in none-dev environment")

    uri = os.environ.get("DS_VAULT_SDK_POSTGRES_URI")
    if not uri:
        raise ValueError("uri has to be set")

    key = os.environ.get("DS_VAULT_SDK_SECRET_KEY")
    if not key:
        raise ValueError("key has not been set")

    repo = PostgresSecretRepository(dsn=uri, table="public.secrets")
    client = DSVaultClient(repository=repo)

    secret_bytes = client.get_secret(key=key)
    print(secret_bytes.decode())


ds_vault_get_secret_round_trip()
