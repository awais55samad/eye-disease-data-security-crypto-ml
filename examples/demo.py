"""Demo: encrypt a synthetic record, hide it, extract it, then tamper."""

from pathlib import Path

from eye_secure import secure_hide, secure_reveal
from eye_secure.stego import GrayImage, load_pgm

ROOT = Path(__file__).resolve().parent
MESSAGE = "EYE-001, modality fundus, date 2025-01-10"
PASSWORD = "change-me"


def main() -> None:
    image = load_pgm(ROOT / "sample_image.pgm")
    stego = secure_hide(image, MESSAGE, PASSWORD)
    print(f"carrier: {image.width}x{image.height}, capacity {image.capacity_bytes()} bytes")
    print(f"revealed: {secure_reveal(stego, PASSWORD)}")

    # Tamper with one pixel and show recovery is refused.
    pixels = list(stego.pixels)
    pixels[50] ^= 0x01
    tampered = GrayImage(stego.width, stego.height, stego.max_value, pixels)
    try:
        secure_reveal(tampered, PASSWORD)
        print("tampering NOT detected (unexpected)")
    except ValueError as exc:
        print(f"tampering detected: {exc}")


if __name__ == "__main__":
    main()
