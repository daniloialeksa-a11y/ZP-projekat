import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. Generate a random 128-bit (16-byte) key instead of 256-bit
key = AESGCM.generate_key(bit_length=128)
aesgcm = AESGCM(key)

# 2. Your data must be in bytes
message = b"Secret data protected by AES-128"

# 3. Generate a fresh 12-byte nonce (this stays the same size for GCM)
nonce = os.urandom(12)

# 4. Encrypt
ciphertext = aesgcm.encrypt(nonce, message, associated_data=None)

# 5. Combine nonce and ciphertext for storage/transmission
encrypted_package = nonce + ciphertext

# -------------------------------------------------------------
# 6. Decrypt (when reading the data back)
extracted_nonce = encrypted_package[:12]
extracted_ciphertext = encrypted_package[12:]

decrypted_message = aesgcm.decrypt(extracted_nonce, extracted_ciphertext, associated_data=None)
print(nonce)
print(extracted_ciphertext)
print(decrypted_message)  # Outputs: Secret data protected by AES-128