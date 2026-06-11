from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import hashlib

from .entries import PrivateKeyEntry, PublicKeyEntry

def generate_rsa_key_pair(name: str, email: str, key_size: int, password: str) -> tuple[PrivateKeyEntry, PublicKeyEntry]:
    """Generates an RSA Key pair, formats them as PEM strings, and returns Key Entries."""
    
    # 1. Generisanje RSA privatnog ključa i javnog ključa
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()

    # 2. Serijalizacija privatnog ključa u PEM format, šifrovanog pomoću prosleđene lozinke
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
        password=password
    )
    
    public_entry = PublicKeyEntry(
        key_id=key_id,
        name=name,
        email=email,
        public_key=public_pem
    )

    return private_entry, public_entry