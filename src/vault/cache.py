from __future__ import annotations
import collections
import time
import typing


class TTLCache:
    """Tiny in-process TTL+LRU cache."""

    def __init__(self, maxsize: int = 1024, ttl_seconds: int = 300) -> None:
        self.maxsize = maxsize
        self.ttl = ttl_seconds
        self._store: collections.OrderedDict[
            typing.Hashable, typing.Tuple[float, typing.Any]
        ] = collections.OrderedDict()

    def _purge_expired(self) -> None:
        now = time.time()
        to_delete = [k for k, (t, _) in self._store.items() if now - t > self.ttl]
        for k in to_delete:
            self._store.pop(k, None)

    def get(self, key: typing.Hashable) -> typing.Optional[typing.Any]:
        self._purge_expired()
        item = self._store.get(key)
        if not item:
            return None

        # move to end (Least Recently Used)
        self._store.move_to_end(key)
        return item[1]

    def set(self, key: typing.Hashable, value: typing.Any) -> None:
        self._purge_expired()
        self._store[key] = (time.time(), value)
        self._store.move_to_end(key)
        if len(self._store) > self.maxsize:
            self._store.popitem(last=False)

    def clear(self) -> None:
        self._store.clear()
