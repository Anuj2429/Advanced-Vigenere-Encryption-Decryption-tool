import os
import base64
import hashlib
from typing import Tuple

from constants import SALT_LEN, PBKDF2_HASH, PBKDF2_ITER, DERIVED_KEY_LEN

# ---- helpers ----

def derive_base_key(password: str, salt: bytes) -> bytes:
    """PBKDF2 to stretch user password into a 32-byte base key."""
    return hashlib.pbkdf2_hmac(
        PBKDF2_HASH,
        password.encode("utf-8"),
        salt,
        PBKDF2_ITER,
        dklen=DERIVED_KEY_LEN
    )

def expand_keystream(base_key: bytes, salt: bytes, length: int) -> bytes:
    """
    Deterministically expand (base_key, salt) into a keystream >= length.
    Uses iterative SHA-256 chaining. Same inputs -> same stream.
    """
    block = hashlib.sha256(base_key + salt).digest()
    out = bytearray(block)
    while len(out) < length:
        block = hashlib.sha256(block + salt).digest()
        out.extend(block)
    return bytes(out[:length])

# ---- multi-pass transforms (byte-wise) ----

def pass_add(data: bytes, ks: bytes) -> bytes:
    return bytes((d + k) & 0xFF for d, k in zip(data, ks))

def pass_xor(data: bytes, ks: bytes) -> bytes:
    return bytes(d ^ k for d, k in zip(data, ks))

def pass_sub(data: bytes, ks: bytes) -> bytes:
    return bytes((d - k) & 0xFF for d, k in zip(data, ks))

# ---- public API ----

def encrypt_bytes(plain: bytes, password: str) -> Tuple[bytes, bytes]:
    """Returns (salt, ciphertext_bytes). Caller decides final packaging."""
    salt = os.urandom(SALT_LEN)
    base_key = derive_base_key(password, salt)
    ks = expand_keystream(base_key, salt, len(plain))

    # Multi-pass: Add -> XOR -> Sub
    stage1 = pass_add(plain, ks)
    stage2 = pass_xor(stage1, ks)
    cipher = pass_sub(stage2, ks)

    return (salt, cipher)

def decrypt_bytes(salt: bytes, cipher: bytes, password: str) -> bytes:
    base_key = derive_base_key(password, salt)
    ks = expand_keystream(base_key, salt, len(cipher))

    # Reverse passes: Add (undo Sub) -> XOR -> Sub (undo Add)
    stage1 = pass_add(cipher, ks)      # undo last Sub
    stage2 = pass_xor(stage1, ks)      # XOR is self-inverse
    plain  = pass_sub(stage2, ks)      # undo first Add

    return plain

# ---- text packaging (for Text Mode) ----

def package_text(salt: bytes, cipher: bytes, delim: str) -> str:
    salt_b64 = base64.b64encode(salt).decode("ascii")
    data_b64 = base64.b64encode(cipher).decode("ascii")
    return f"{salt_b64}{delim}{data_b64}"

def unpackage_text(pkg: str, delim: str) -> Tuple[bytes, bytes]:
    salt_b64, data_b64 = pkg.split(delim, 1)
    salt = base64.b64decode(salt_b64.encode("ascii"))
    data = base64.b64decode(data_b64.encode("ascii"))
    return (salt, data)
