from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Iterator

from entries import PublicKeyEntry


@dataclass(slots=True)
class PublicKeyRing:
    entries: dict[str, PublicKeyEntry] = field(default_factory=dict)

    # ---------- osnovne operacije ----------

    def add(self, entry: PublicKeyEntry) -> None:
        self.entries[entry.key_id] = entry

    def get(self, key_id: str) -> PublicKeyEntry:
        try:
            return self.entries[key_id]
        except KeyError:
            raise KeyError(f"Public key not found: {key_id}")

    def remove(self, key_id: str) -> bool:
        """Vraca True ako je unos postojao i obrisan je, inace False."""
        return self.entries.pop(key_id, None) is not None

    def __contains__(self, key_id: str) -> bool:
        return key_id in self.entries

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[PublicKeyEntry]:
        return iter(self.entries.values())

    # ---------- perzistencija ----------

    def to_dict(self) -> dict:
        result = {}
        for key_id, entry in self.entries.items():
            entry_dict = asdict(entry)
            if isinstance(entry_dict.get("created_at"), datetime):
                entry_dict["created_at"] = entry_dict["created_at"].isoformat()
            result[key_id] = entry_dict
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "PublicKeyRing":
        ring = cls()
        for key_id, entry_data in data.items():
            entry_data = dict(entry_data)
            if isinstance(entry_data.get("created_at"), str):
                entry_data["created_at"] = datetime.fromisoformat(entry_data["created_at"])
            ring.entries[key_id] = PublicKeyEntry(**entry_data)
        return ring

    def save(self, file_path: str | Path) -> None:
        """Javni kljucevi nisu tajni, cuvaju se u citljivom JSON fajlu."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, file_path: str | Path) -> "PublicKeyRing":
        path = Path(file_path)
        if not path.exists():
            return cls()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)