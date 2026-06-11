from dataclasses import dataclass, field
from typing import Iterator
from .entries import PrivateKeyEntry


@dataclass(slots=True)
class PrivateKeyRing:
    entries: dict[str, PrivateKeyEntry] = field(default_factory=dict)

    def add(self, entry: PrivateKeyEntry) -> None:
        self.entries[entry.key_id] = entry

    def get(self, key_id: str) -> PrivateKeyEntry:
        try:
            return self.entries[key_id]
        except KeyError:
            raise KeyError(f"Private key not found: {key_id}")

    def remove(self, key_id: str) -> None:
        self.entries.pop(key_id, None)

    def __iter__(self) -> Iterator[PrivateKeyEntry]:
        return iter(self.entries.values())