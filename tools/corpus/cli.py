from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from tools.corpus.validate import validate_root


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skan-corpus", description="Skan fingerprint corpus tools")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("verify", "stats"):
        command = sub.add_parser(name)
        command.add_argument("--root", type=Path, default=Path("."))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        summary = validate_root(args.root)
    except (OSError, ValueError) as exc:
        print(f"corpus {args.command} failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
