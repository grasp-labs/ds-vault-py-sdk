# DS Vault Python SDK

## Features

- GetSecret
- TTL + LRD Cache (KEK & records)
- Psql and Memory repositories

## Quickstart

### Install

`With postgres`:

```bash
pip install "ds-vault-py-sdk[postgres]"
```

`Memory only`:

```bash
pip install ds-vault-py-sdk
```

### Usage

Postgres - plain:

```python
from vault import DSVaultClient
from vault.repositories.postgres import PostgresSecretRepository

repo = PostgresSecretRepository(
    dsn="postgresql://user:pass@host:5432/db",
    table="public.secrets",
)

client = DSVaultClient(repository=repo)

secret_bytes = client.get_secret(key=key)
print(secret_bytes.decode())
```

Managed KMS context:

```python
client = DSVaultClient(
    repository=repo,
    encryption_context_defaults={"app": "payments-api", "env": "prod"},
)
```

### Tests

Execute tests by setting environment variables to
manage import paths, and call pytest.

```bash
export PYTHONPATH="src"
pipenv run pytest
```

## Environment

Currently support `dev` and `prod` environment,
defined by setting environment variable `BUILDING_MODE`,
e.g.:

```bash
export BUILDING_MODE="dev"
```
