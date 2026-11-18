"""Layered security: encrypt first, then hide in an image.

Layer 1 — cryptography: the record is encrypted (see ``crypto``).
Layer 2 — steganography: the encrypted bytes are hidden in a
grayscale image (see ``stego``).

Recovery reverses the layers: extract from the image, then decrypt.
Integrity is verified during decryption, so tampering with the
image, the ciphertext, or the password is detected.
"""

from __future__ import annotations

from .crypto import decrypt, encrypt
from .stego import GrayImage, extract, hide


def secure_hide(image: GrayImage, message: str, password: str) -> GrayImage:
    """Encrypt ``message`` and hide it in ``image``. Returns a new image."""
    blob = encrypt(message.encode("utf-8"), password)
    return hide(image, blob)


def secure_reveal(image: GrayImage, password: str) -> str:
    """Extract and decrypt the hidden message from ``image``."""
    blob = extract(image)
    return decrypt(blob, password).decode("utf-8")
