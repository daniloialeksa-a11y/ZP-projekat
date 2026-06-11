from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True, slots=True)
class PublicKeyEntry:
    key_id: str
    user_id: str
    public_key: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True, slots=True)
class PrivateKeyEntry:
    key_id: str
    user_id: str
    private_key: str
    public_key: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
