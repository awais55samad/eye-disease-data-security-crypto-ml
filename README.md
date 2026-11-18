# Eye Disease Data Security — Crypto + Steganography

A layered intelligent framework for securing eye disease data through
the fusion of cryptography and steganographic techniques.

This is an **original, independent implementation inspired by** the 2025
paper *“A ROBUST LAYERED INTELLIGENT FRAMEWORK FOR SECURING EYE DISEASE
DATA THROUGH THE FUSION OF CRYPTOGRAPHY AND STEGANOGRAPHIC TECHNIQUES”*.
It is **not** the official code from that paper, and it does not claim
to reproduce its results. It implements the core idea in a small,
readable form: a data record is encrypted first, then hidden inside a
grayscale image with least-significant-bit (LSB) steganography, so that
the stored image carries the record without visibly changing it.

This project does **not** perform medical diagnosis, screening, or
treatment decisions. It is a data-security prototype only.

## What it does

- Derives an encryption key from a password with PBKDF2-HMAC-SHA256.
- Encrypts a record with a SHA-256 counter-mode stream cipher (XOR),
  with a SHA-256 integrity tag over the ciphertext.
- Hides the encrypted bytes in a grayscale image by LSB embedding,
  with a 32-bit length header so extraction knows how much to read.
- Extracts the hidden bytes, verifies integrity, and decrypts them.
- Detects tampering: a wrong password, a changed ciphertext, or a
  changed image pixel makes verification fail instead of returning
  altered data.
- Ships with a command-line tool, a PGM image example, and tests.
  Pure Python standard library only — no external packages.

## Quick start

```bash
python3 -m pip install -e .
python3 examples/demo.py
```

That encrypts a short synthetic record, hides it in the sample
grayscale image, extracts it again, and shows that changing one
pixel is detected.

### Command line

```bash
# Encrypt a record and hide it in an image (PGM, P2 format)
eye-secure hide --image examples/sample_image.pgm \
  --message "EYE-001, modality fundus, date 2025-01-10" \
  --password "change-me" --out stego.pgm

# Extract and decrypt from a stego image
eye-secure reveal --image stego.pgm --password "change-me"
```

The sample image is a small 64x64 grayscale PGM (P2, plain ASCII).
Any P2 PGM image of the same format can be used as a carrier.

## Project layout

```
src/eye_secure/
  crypto.py   # PBKDF2 key derivation, stream cipher, integrity tag
  stego.py    # Grayscale image (PGM) and LSB hide / extract
  layered.py  # Encrypt-then-hide, extract-then-decrypt
  cli.py      # Command-line interface
examples/
  sample_image.pgm
  demo.py
tests/
  test_eye_secure.py
```

## Security notes

This is experimental research code, version 0.1.0. The stream cipher
here is a teaching prototype built from SHA-256; it is **not** a
production replacement for AES-GCM or another audited authenticated
encryption scheme, and it has not been audited for security. Do not
use it to protect real patient data, and do not rely on steganography
alone to keep data secret — the encryption layer is what protects
confidentiality.

## Author

**Engr. Muhammad Awais Khan** — Bahauddin Zakariya University, Multan (Pakistan)

Google Scholar profile: https://scholar.google.com/citations?hl=en&user=c4UawvgAAAAJ

## Status

Experimental research code, version 0.1.0.

## License

MIT — see `LICENSE`.
