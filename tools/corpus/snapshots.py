from __future__ import annotations

import hashlib
from pathlib import Path


_CHUNK_SIZE = 1024 * 1024


def _valid_sha256(value: str) -> bool:
    prefix = "sha256:"
    if not value.startswith(prefix):
        return False
    digest = value[len(prefix):]
    return len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_SIZE):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def verify_snapshot(path: Path, expected_hash: str) -> None:
    if not _valid_sha256(expected_hash):
        raise ValueError("expected snapshot hash must be sha256:<64 lowercase hex chars>")
    actual_hash = sha256_file(path)
    if actual_hash != expected_hash:
        raise ValueError(
            f"snapshot hash mismatch: expected {expected_hash}, got {actual_hash}"
        )
