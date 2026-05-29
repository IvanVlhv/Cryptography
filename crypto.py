import os
import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

NONCE_SIZE = 12


# --- Password hashing ---

def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return False


# --- Key exchange ---

def generate_keypair() -> tuple[X25519PrivateKey, bytes]:
    private_key = X25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private_key, public_key_bytes


def derive_shared_key(private_key: X25519PrivateKey, peer_public_key_bytes: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    raw_shared = private_key.exchange(peer_public_key)
    # HKDF extracts uniform key material from the raw ECDH group element
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"securechat-v1-session-key",
    ).derive(raw_shared)


# --- Authenticated encryption (ChaCha20-Poly1305) ---

def encrypt_message(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    nonce = os.urandom(NONCE_SIZE)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, associated_data or None)
    return nonce + ct  # nonce prepended for receiver


def decrypt_message(key: bytes, ciphertext_with_nonce: bytes, associated_data: bytes = b"") -> bytes:
    if len(ciphertext_with_nonce) < NONCE_SIZE + 16:
        raise ValueError("Ciphertext too short")
    nonce = ciphertext_with_nonce[:NONCE_SIZE]
    ct = ciphertext_with_nonce[NONCE_SIZE:]
    return ChaCha20Poly1305(key).decrypt(nonce, ct, associated_data or None)


# --- Serialisation helpers ---

def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def b64decode(data: str) -> bytes:
    data = data.strip()
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


# --- Challenge-response ---

def generate_challenge() -> bytes:
    return os.urandom(32)
