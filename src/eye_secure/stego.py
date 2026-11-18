"""LSB steganography in a grayscale image (PGM, P2 plain format).

The image is a flat list of pixel values (0-255) with a width and
height. A payload is stored as a 32-bit big-endian length header
followed by the payload bytes, one bit per pixel in the least
significant bit. Changing a pixel's LSB is invisible to the eye
for ordinary grayscale images.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class GrayImage:
    width: int
    height: int
    max_value: int
    pixels: list[int]

    def __post_init__(self) -> None:
        if self.width <= 0 or self.height <= 0:
            raise ValueError("width and height must be positive")
        if self.max_value <= 0 or self.max_value > 255:
            raise ValueError("max_value must be between 1 and 255")
        if len(self.pixels) != self.width * self.height:
            raise ValueError("pixel count does not match width x height")
        if any(p < 0 or p > self.max_value for p in self.pixels):
            raise ValueError("pixel values out of range")

    def capacity_bytes(self) -> int:
        """Usable payload bytes (after the 32-bit length header)."""
        return max(0, (len(self.pixels) - 32) // 8)

    def copy(self) -> "GrayImage":
        return GrayImage(self.width, self.height, self.max_value, list(self.pixels))


def load_pgm(path: str | Path) -> GrayImage:
    """Load a plain PGM (P2) file. Comments (``# ...``) are skipped."""
    tokens: list[str] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if line:
                tokens.extend(line.split())
    if len(tokens) < 4 or tokens[0] != "P2":
        raise ValueError("only plain PGM (P2) files are supported")
    width, height, max_value = int(tokens[1]), int(tokens[2]), int(tokens[3])
    pixels = [int(t) for t in tokens[4:]]
    return GrayImage(width, height, max_value, pixels)


def save_pgm(image: GrayImage, path: str | Path) -> None:
    """Save an image as a plain PGM (P2) file."""
    lines = ["P2", f"{image.width} {image.height}", str(image.max_value)]
    row = []
    for i, pixel in enumerate(image.pixels):
        row.append(str(pixel))
        if len(row) == 16 or i == len(image.pixels) - 1:
            lines.append(" ".join(row))
            row = []
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _bits_of(data: bytes) -> list[int]:
    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def hide(image: GrayImage, payload: bytes) -> GrayImage:
    """Return a copy of ``image`` with ``payload`` hidden in its LSBs."""
    if len(payload) > image.capacity_bytes():
        raise ValueError(
            f"payload too large: {len(payload)} bytes, capacity {image.capacity_bytes()} bytes"
        )
    header = len(payload).to_bytes(4, "big")
    bits = _bits_of(header + payload)
    pixels = list(image.pixels)
    for i, bit in enumerate(bits):
        pixels[i] = (pixels[i] & ~1) | bit
    return GrayImage(image.width, image.height, image.max_value, pixels)


def extract(image: GrayImage) -> bytes:
    """Extract the hidden payload from an image made by :func:`hide`."""
    bits = [p & 1 for p in image.pixels]
    if len(bits) < 32:
        raise ValueError("image too small to hold a payload")
    length = 0
    for bit in bits[:32]:
        length = (length << 1) | bit
    if length < 0 or length > image.capacity_bytes():
        raise ValueError("no valid hidden payload found (length header invalid)")
    payload_bits = bits[32:32 + length * 8]
    if len(payload_bits) < length * 8:
        raise ValueError("image too small for the stated payload length")
    out = bytearray()
    for i in range(0, len(payload_bits), 8):
        byte = 0
        for bit in payload_bits[i:i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)
