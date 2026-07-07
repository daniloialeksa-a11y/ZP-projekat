from __future__ import annotations

from pathlib import Path
PRIVATE_PATH = "private_keyring.json"
PUBLIC_PATH = "public_keyring.json"
from private_key_ring import PrivateKeyRing
from public_key_ring import PublicKeyRing
from rsa_key_gen import generate_rsa_key_pair  # funkcija iz tvog crypto modula


class KeyManager:
    """
    Objedinjuje PrivateKeyRing i PublicKeyRing i garantuje da uvek
    ostanu konzistentni (isti key_id postoji u oba ringa ili ni u jednom).
    """

    def __init__(
        self,
        private_ring: PrivateKeyRing | None = None,
        public_ring: PublicKeyRing | None = None,
    ) -> None:
        self.private_ring = private_ring or PrivateKeyRing()
        self.public_ring = public_ring or PublicKeyRing()

    # ---------- generisanje / brisanje para ----------

    def generate_and_add_pair(
        self, name: str, email: str, key_size: int, password: str
    ) -> str:
        """Generise novi RSA par, dodaje ga u oba ringa i vraca key_id."""
        private_entry, public_entry = generate_rsa_key_pair(
            name, email, key_size, password
        )
        self.private_ring.add(private_entry)
        self.public_ring.add(public_entry)
        return private_entry.key_id

    def is_own_key_pair(self, key_id: str) -> bool:
        return key_id in self.private_ring              # vratice true ako postoji privatni kljuc sa istim id-om ( da li je uvezen ili ne )

    def delete_pair(self, key_id: str) -> bool:
        """
        Brise privatni i javni kljuc sa istim key_id iz oba ringa.
        Vraca True ako je bar jedan od njih zaista postojao.
        """
        removed_private = self.private_ring.remove(key_id)
        removed_public = self.public_ring.remove(key_id)
        return removed_private or removed_public

    def import_public_only(self, public_entry) -> None:
        """Uvoz tudjeg javnog kljuca (nema odgovarajuceg privatnog)."""
        self.public_ring.add(public_entry)

    # ---------- perzistencija oba ringa odjednom ----------

    def save_all(self, private_path: str | Path, public_path: str | Path) -> None:
        self.private_ring.save(private_path)
        self.public_ring.save(public_path)

    @classmethod
    def load_all(
        cls, private_path: str | Path, public_path: str | Path
    ) -> "KeyManager":
        private_ring = PrivateKeyRing.load(private_path)
        public_ring = PublicKeyRing.load(public_path)
        return cls(private_ring, public_ring)


if __name__ == "__main__":
    # 1. Učitaj postojeće stanje sa diska (ako fajlovi ne postoje, load() vraća prazan ring)
    manager = KeyManager.load_all(PRIVATE_PATH, PUBLIC_PATH)

    # 2. Dodaj novi ključ NA POSTOJEĆI ring u memoriji
    key_id = manager.generate_and_add_pair("Leon", "leon.vi@example.com", 2048, "grofica")

    # 3. Sačuvaj — sada fajl sadrži i stare i novi ključ
    manager.save_all(PRIVATE_PATH, PUBLIC_PATH)
    print("Ringovi sacuvani na disk.")

    loaded = KeyManager.load_all(PRIVATE_PATH, PUBLIC_PATH)
    assert key_id in loaded.private_ring
    assert key_id in loaded.public_ring
    print("Ucitavanje sa diska uspesno, ringovi su konzistentni.")

    # 4. Obrisi par i ODMAH sacuvaj promenu, inace ostaje samo u memoriji
    manager.delete_pair(key_id)
    manager.save_all(PRIVATE_PATH, PUBLIC_PATH)
    assert key_id not in manager.private_ring
    assert key_id not in manager.public_ring
    print("Par kljuceva uspesno obrisan iz oba ringa (i sa diska).")

    print(f"Broj privatnih kljuceva: {len(manager.private_ring)}")
    print(f"Broj javnih kljuceva: {len(manager.public_ring)}")