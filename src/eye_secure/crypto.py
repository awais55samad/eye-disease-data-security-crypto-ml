"""Password-based encryption with an integrity tag (stdlib only).

Key derivation: PBKDF2-HMAC-SHA256.
Cipher: a SHA-256 counter-mode stream cipher (XOR with a keystream).
Integrity: HMAC-SHA256 over the ciphertext, verified before decrypting.

Wire format: ``salt (16 bytes) || tag (32 bytes) || ciphertext``.

This is a teaching prototype, not a production replacement for an
audited authenticated-encryption scheme such as AES-GCM.
"""

from __future__ import annotations

import hashlib
import hmac
import os

SALT_LEN = 16
TAG_LEN = 32
ITERATIONS = 200_000


def _keystream(key: bytes, length: int) -> bytes:
    """Generate ``length`` keystream bytes from ``key`` (counter mode)."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(key + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(out[:length])


def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=32
    )


def encrypt(plaintext: bytes, password: str, salt: bytes | None = None) -> bytes:
    """Encrypt ``plaintext``. Returns ``salt || tag || ciphertext``."""
    if not password:
        raise ValueError("password must not be empty")
    salt = salt if salt is not None else os.urandom(SALT_LEN)
    if len(salt) != SALT_LEN:
        raise ValueError(f"salt must be {SALT_LEN} bytes")
    key = _derive_key(password, salt)
    keystream = _keystream(key, len(plaintext))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
    tag = hmac.new(key, ciphertext, hashlib.sha256).digest()
    return salt + tag + ciphertext


def decrypt(blob: bytes, password: str) -> bytes:
    """Decrypt a blob from :func:`encrypt`, verifying its integrity first.

    Raises :class:`ValueError` on a wrong password, a truncated blob,
    or any tampering with the ciphertext.
    """
    if not password:
        raise ValueError("password must not be empty")
    if len(blob) < SALT_LEN + TAG_LEN:
        raise ValueError("encrypted data is too short")
    salt, tag, ciphertext = blob[:SALT_LEN], blob[SALT_LEN:SALT_LEN + TAG_LEN], blob[SALT_LEN + TAG_LEN:]
    key = _derive_key(password, salt)
    expected = hmac.new(key, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("integrity check failed: wrong password or tampered data")
    keystream = _keystream(key, len(ciphertext))
    return bytes(c ^ k for c, k in zip(ciphertext, keystream))
