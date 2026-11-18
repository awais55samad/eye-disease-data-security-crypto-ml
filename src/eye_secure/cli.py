"""Command-line interface: ``eye-secure hide|reveal``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .layered import secure_hide, secure_reveal
from .stego import load_pgm, save_pgm


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="eye-secure",
        description="Encrypt a record and hide it in a grayscale image.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    hide_cmd = sub.add_parser("hide", help="Encrypt a message and hide it in an image")
    hide_cmd.add_argument("--image", required=True, help="Input PGM (P2) image")
    hide_cmd.add_argument("--message", required=True)
    hide_cmd.add_argument("--password", required=True)
    hide_cmd.add_argument("--out", required=True, help="Output PGM image")

    reveal_cmd = sub.add_parser("reveal", help="Extract and decrypt a hidden message")
    reveal_cmd.add_argument("--image", required=True, help="Stego PGM image")
    reveal_cmd.add_argument("--password", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "hide":
            image = load_pgm(args.image)
            stego = secure_hide(image, args.message, args.password)
            save_pgm(stego, Path(args.out))
            print(f"hidden {len(args.message.encode('utf-8'))} byte(s) -> {args.out}")
            return 0
        if args.command == "reveal":
            image = load_pgm(args.image)
            print(secure_reveal(image, args.password))
            return 0
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
