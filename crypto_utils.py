import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the master password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(master_password.encode())


def encrypt_password(master_password: str, salt: bytes, plaintext: str) -> tuple:
    """Encrypt plaintext using AES-256-GCM. Returns (ciphertext, iv)."""
    key = derive_key(master_password, salt)
    iv = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(iv, plaintext.encode(), None)
    return ciphertext, iv


def decrypt_password(master_password: str, salt: bytes, iv: bytes, ciphertext: bytes) -> str:
    """
    Decrypt ciphertext using AES-256-GCM.
    Raises an exception if master password is wrong or data is corrupted.
    """
    key = derive_key(master_password, salt)
    return AESGCM(key).decrypt(iv, ciphertext, None).decode()
