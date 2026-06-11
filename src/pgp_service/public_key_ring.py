from dataclasses import dataclass, field
from typing import Iterator
from .entries import PublicKeyEntry


@dataclass(slots=True)
class PublicKeyRing:
    entries: dict[str, PublicKeyEntry] = field(default_factory=dict)

    def add(self, entry: PublicKeyEntry) -> None:
        self.entries[entry.key_id] = entry

    def update(self, entry: PublicKeyEntry) -> None:
        self.entries[entry.key_id] = entry

    def get(self, key_id: str) -> PublicKeyEntry:
        try:
            return self.entries[key_id]
        except KeyError:
            raise KeyError(f"Public key not found: {key_id}")

    def remove(self, key_id: str) -> None:
        self.entries.pop(key_id, None)

    def __iter__(self) -> Iterator[PublicKeyEntry]:
        return iter(self.entries.values())