from __future__ import annotations
import typing
from .base import SecretRepository
from ..models import SecretRecord


class InMemorySecretRepository(SecretRepository):
    def __init__(self, data: typing.Dict[str, SecretRecord] | None = None):
        self._data = data or {}

    def get_secret_record(self, *, key: str) -> typing.Optional[SecretRecord]:
        """Fetch a SecretRecord from the datastore by id + tenant + store + environment."""
        return self._data.get(key)

    def __len__(self):
        return len(self._data)

    def __str___(self):
        return self.__class__.__name__

    def __next__(self):
        return next(self._data)

    def __repr__(self):
        return f"{self.__class__.__name__}: {len(self)}"
