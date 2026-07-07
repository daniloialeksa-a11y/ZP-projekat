import os
import string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidSignature
import hashlib
import zlib
import base64
from entries import PrivateKeyEntry, PublicKeyEntry

def upisiNaLokaciju(pem_data: str, file_path: str) -> None:
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(pem_data)

# ---------- Import i export funkcije ----------

def export_private_key(private_key, password: str) -> str:
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        )
    )
    return pem_bytes.decode("utf-8")


def export_public_key(public_key) -> str:
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_bytes.decode("utf-8")


def import_public_key(pem: str):
    return serialization.load_pem_public_key(
        pem.encode("utf-8")
    )

def import_private_key(pem: str, password: str):
    try:
        return serialization.load_pem_private_key(
            pem.encode("utf-8"),
            password=password.encode("utf-8")
        )
    except (ValueError, TypeError, InvalidKey) as exc:
        raise ValueError("Invalid password or corrupted key") from exc

# ---------- Kraj import i export funkcija ----------

#------------------------------------------------------------------------------------

# ---------- Funkcije za rad sa privatnim ključevima ----------


def unlock_private_key(entry: PrivateKeyEntry, password: str):
    return import_private_key(entry.private_key, password)


def validate_private_key(entry: PrivateKeyEntry, password: str) -> bool:
    try:
        import_private_key(entry.private_key, password)
        return True
    except ValueError:
        return False


# ---------- Kraj funkcija za rad sa privatnim ključevima ----------

#------------------------------------------------------------------------------------

# ---------- Sekcija za potpisivanje poruka ----------

def sign_message(private_entry: PrivateKeyEntry, password: str, message: bytes):
    private_key = unlock_private_key(private_entry, password)
    return private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA1(),
    )


def verify_signature(public_entry: PublicKeyEntry, message: bytes, signature: bytes) -> bool:
    public_key = import_public_key(public_entry.public_key)
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA1(),
        )
        return True
    except InvalidSignature:
        return False
    
# ---------- Kraj sekcije za potpisivanje poruka ----------

def compress(data: bytes) -> bytes:
    return zlib.compress(data)

def decompress(data: bytes) -> bytes:
    return zlib.decompress(data)

def radix64_encode(data: bytes) -> bytes:
    return base64.b64encode(data)

def radix64_decode(data: bytes) -> bytes:
    return base64.b64decode(data)

def tripleDesEncrypt(message: bytes, key: bytes) -> bytes:
    iv = os.urandom(8) 

    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(message) + padder.finalize()

    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext

def tripleDesDecrypt(encrypted_package: bytes, key: bytes) -> bytes:
    iv = encrypted_package[:8]
    ciphertext = encrypted_package[8:]

    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(64).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def aesEncrypt(message: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, message, associated_data=None)
    return nonce + ciphertext

def aesDecrypt(encrypted_package: bytes, key: bytes) -> bytes:
    nonce = encrypted_package[:12]
    ciphertext = encrypted_package[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)

def generate_rsa_key_pair(name: str, email: str, key_size: int, password: str) -> tuple[PrivateKeyEntry, PublicKeyEntry]:
    #Generise RSA ključeve, serijalizuje ih u PEM format, i kreira DataClass objekte za privatni i javni ključ.

    if key_size not in (1024, 2048):
        raise ValueError("Velicina kljuca mora da bude ili 1024 ili 2048")

    # 1. Generisanje RSA privatnog ključa i javnog ključa
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()

    # 2. Serijalizacija privatnog ključa u PEM format, šifrovanog pomoću prosleđene lozinke
    # Lozinka se koristi samo za zaštitu privatnog ključa; ne čuva se u entry objektu.
    private_pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
    )
    private_pem = private_pem_bytes.decode('utf-8')

    # 3. Serijalizacija javnog ključa u PEM format
    public_pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_pem = public_pem_bytes.decode('utf-8')

    # 4. Formiranje ID-a ključa (Key ID)
    # Kreiramo pseudo-Key ID od 16 karaktera na osnovu SHA-1 heša PEM-a javnog ključa
    # (U standardnom PGP-u, ovo se obično izvodi iz paketa javnog ključa, ali ovo je ovde dovoljno dobro)
    key_hash = hashlib.sha1(public_pem_bytes).hexdigest()
    key_id = key_hash[-16:].upper()

    # 5. Kreiranje objekata za naše DataClass modele
    private_entry = PrivateKeyEntry(
        key_id=key_id,
        name=name,
        email=email,
        private_key=private_pem,
        public_key=public_pem,
        key_length=key_size,
    )
    
    public_entry = PublicKeyEntry(
        key_id=key_id,
        name=name,
        email=email,
        public_key=public_pem,
        key_length=key_size
    )

    return private_entry, public_entry

# a = ""
# b = "" 
# [a,b] = generate_rsa_key_pair("Danilo", "danilo@example.com", 2048, "password")
# print ([a,b])