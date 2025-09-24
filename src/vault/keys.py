import uuid


def make_key(id: uuid.UUID, tenant_id: uuid.UUID, store: str, environment: str) -> str:
    return f"/ds/vault/{store}/{tenant_id}/{id}/{environment}"
