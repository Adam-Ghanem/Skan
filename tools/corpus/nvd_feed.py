from __future__ import annotations

import json
from pathlib import Path
import re
from typing import TextIO


_PRODUCTS_START = re.compile(r'"products"\s*:\s*\[')
_READ_SIZE = 1024 * 1024


def _write_chunk(output_dir: Path, index: int, products: list[object]) -> None:
    path = output_dir / f"page-{index:05d}.json"
    payload = json.dumps(
        {"products": products},
        ensure_ascii=False,
        separators=(",", ":"),
    ) + "\n"
    path.write_text(payload, encoding="utf-8")


def _read_until_products(handle: TextIO) -> tuple[str, int]:
    buffer = ""
    while len(buffer) <= _READ_SIZE:
        chunk = handle.read(_READ_SIZE - len(buffer) + 1)
        if not chunk:
            break
        buffer += chunk
        match = _PRODUCTS_START.search(buffer)
        if match is not None:
            return buffer, match.end()
    raise ValueError("NVD CPE feed requires a products array near the document start")


def split_nvd_cpe_feed(
    source_path: Path,
    output_dir: Path,
    *,
    chunk_size: int = 10_000,
) -> dict[str, int]:
    """Stream the NVD CPE 2.0 products array into deterministic JSON chunks.

    This deliberately avoids loading the full nightly dictionary into memory. Each
    generated chunk retains the adapter-compatible ``{"products": [...]}`` shape.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    source_path = Path(source_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    for stale in output_dir.glob("page-*.json"):
        stale.unlink()

    decoder = json.JSONDecoder()
    total_products = 0
    chunk_index = 0
    pending: list[object] = []

    with source_path.open("r", encoding="utf-8") as handle:
        buffer, cursor = _read_until_products(handle)
        eof = False

        while True:
            while True:
                while cursor < len(buffer) and buffer[cursor].isspace():
                    cursor += 1
                if cursor < len(buffer) and buffer[cursor] == ",":
                    cursor += 1
                    continue
                break

            if cursor < len(buffer) and buffer[cursor] == "]":
                break

            while True:
                try:
                    item, next_cursor = decoder.raw_decode(buffer, cursor)
                    break
                except json.JSONDecodeError as exc:
                    if eof:
                        raise ValueError(f"malformed NVD CPE products array: {exc}") from exc
                    if cursor:
                        buffer = buffer[cursor:]
                        cursor = 0
                    more = handle.read(_READ_SIZE)
                    if more:
                        buffer += more
                    else:
                        eof = True

            if not isinstance(item, dict):
                raise ValueError("NVD CPE products array entries must be objects")
            pending.append(item)
            total_products += 1
            cursor = next_cursor

            if len(pending) == chunk_size:
                _write_chunk(output_dir, chunk_index, pending)
                chunk_index += 1
                pending = []

            if cursor > _READ_SIZE:
                buffer = buffer[cursor:]
                cursor = 0

        if pending:
            _write_chunk(output_dir, chunk_index, pending)
            chunk_index += 1

    return {
        "products": total_products,
        "chunks": chunk_index,
        "chunk_size": chunk_size,
    }
