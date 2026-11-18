import unittest
from pathlib import Path

from eye_secure import decrypt, encrypt, secure_hide, secure_reveal
from eye_secure.stego import GrayImage, extract, hide, load_pgm

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
PASSWORD = "test-password"
MESSAGE = "EYE-001, modality fundus, date 2025-01-10"


def _image(width=16, height=16):
    pixels = [(x * 7 + y * 11) % 256 for y in range(height) for x in range(width)]
    return GrayImage(width, height, 255, pixels)


class TestCrypto(unittest.TestCase):
    def test_encrypt_decrypt_round_trip(self):
        blob = encrypt(MESSAGE.encode(), PASSWORD)
        self.assertEqual(decrypt(blob, PASSWORD).decode(), MESSAGE)

    def test_wrong_password_fails(self):
        blob = encrypt(MESSAGE.encode(), PASSWORD)
        with self.assertRaises(ValueError):
            decrypt(blob, "wrong-password")

    def test_tampered_ciphertext_fails(self):
        blob = bytearray(encrypt(MESSAGE.encode(), PASSWORD))
        blob[-1] ^= 0x01
        with self.assertRaises(ValueError):
            decrypt(bytes(blob), PASSWORD)

    def test_empty_password_rejected(self):
        with self.assertRaises(ValueError):
            encrypt(b"hello", "")


class TestStego(unittest.TestCase):
    def test_hide_extract_round_trip(self):
        image = _image()
        stego = hide(image, b"secret payload")
        self.assertEqual(extract(stego), b"secret payload")
        # Only LSBs change: every pixel differs by at most 1.
        self.assertTrue(all(abs(a - b) <= 1 for a, b in zip(image.pixels, stego.pixels)))

    def test_payload_too_large(self):
        image = _image(4, 4)
        with self.assertRaises(ValueError):
            hide(image, b"x" * 100)

    def test_sample_image_loads(self):
        image = load_pgm(EXAMPLES / "sample_image.pgm")
        self.assertEqual((image.width, image.height), (64, 64))


class TestLayered(unittest.TestCase):
    def test_secure_hide_reveal_round_trip(self):
        image = load_pgm(EXAMPLES / "sample_image.pgm")
        stego = secure_hide(image, MESSAGE, PASSWORD)
        self.assertEqual(secure_reveal(stego, PASSWORD), MESSAGE)

    def test_tampered_pixel_detected(self):
        image = load_pgm(EXAMPLES / "sample_image.pgm")
        stego = secure_hide(image, MESSAGE, PASSWORD)
        pixels = list(stego.pixels)
        pixels[50] ^= 0x01
        tampered = GrayImage(stego.width, stego.height, stego.max_value, pixels)
        with self.assertRaises(ValueError):
            secure_reveal(tampered, PASSWORD)

    def test_wrong_password_on_layered(self):
        image = load_pgm(EXAMPLES / "sample_image.pgm")
        stego = secure_hide(image, MESSAGE, PASSWORD)
        with self.assertRaises(ValueError):
            secure_reveal(stego, "wrong-password")


if __name__ == "__main__":
    unittest.main()
