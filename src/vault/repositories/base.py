from __future__ import annotations
from abc import ABC, abstractmethod
from uuid import UUID
from typing import Optional
from ..models import Environment, SecretRecord, Store


class SecretRepository(ABC):
    @abstractmethod
    def get_secret_record(self, *, key: str) -> Optional[SecretRecord]:
        """Fetch a SecretRecord from the datastore by id + tenant + store + environment."""
        raise NotImplementedError

    @staticmethod
    def generate_key(
        id: UUID, tenant_id: UUID, store: Store, environment: Environment
    ) -> str:
        return f"/ds_vault/{store}/{tenant_id}/{id}/{environment}"
