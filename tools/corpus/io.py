from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any, Iterable, Mapping

from tools.corpus.model import (
    CanonicalRecord,
    CanonicalRecordError,
    parse_record,
    record_to_mapping,
)
from tools.corpus.sources import SourcePolicy


_MAXIMUM_FILE_BYTES = 16 * 1024 * 1024
_MAXIMUM_LINE_BYTES = 64 * 1024
_MAXIMUM_RECORDS = 10_000


class CorpusIOError(ValueError):
    """A canonical corpus file violated its bounded JSONL contract."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CorpusIOError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise CorpusIOError(f"non-standard JSON constant is forbidden: {value}")


def _parse_bounded_int(value: str) -> int:
    if len(value.removeprefix("-")) > 20:
        raise CorpusIOError("invalid JSON integer: exceeds 20 digits")
    return int(value)


def _decode_line(raw_line: bytes, line_number: int) -> Mapping[str, Any]:
    if not raw_line.endswith(b"\n"):
        raise CorpusIOError(f"line {line_number} must end with LF")
    if raw_line.endswith(b"\r\n"):
        raise CorpusIOError(f"line {line_number} must use LF without CR")
    try:
        text = raw_line[:-1].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CorpusIOError(f"line {line_number} must be valid UTF-8") from exc
    if not text:
        raise CorpusIOError(f"line {line_number} must not be blank")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
            parse_int=_parse_bounded_int,
        )
    except CorpusIOError:
        raise
    except json.JSONDecodeError as exc:
        raise CorpusIOError(f"line {line_number} is invalid JSON: {exc.msg}") from exc
    except (ValueError, RecursionError) as exc:
        raise CorpusIOError(f"line {line_number} is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise CorpusIOError(f"line {line_number} must contain a JSON object")
    return value


def load_jsonl(
    path: Path,
    sources: Mapping[str, SourcePolicy],
    *,
    expected_kind: str | None = None,
    allow_empty: bool = False,
) -> tuple[CanonicalRecord, ...]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise CorpusIOError(f"cannot stat corpus file: {exc}") from exc
    if size > _MAXIMUM_FILE_BYTES:
        raise CorpusIOError(f"file exceeds {_MAXIMUM_FILE_BYTES} bytes")

    records: list[CanonicalRecord] = []
    identifiers: set[str] = set()
    bytes_read = 0
    try:
        with path.open("rb") as stream:
            line_number = 0
            while True:
                raw_line = stream.readline(_MAXIMUM_LINE_BYTES + 1)
                if not raw_line:
                    break
                line_number += 1
                bytes_read += len(raw_line)
                if len(raw_line) > _MAXIMUM_LINE_BYTES:
                    raise CorpusIOError(
                        f"line {line_number} exceeds {_MAXIMUM_LINE_BYTES} bytes"
                    )
                if bytes_read > _MAXIMUM_FILE_BYTES:
                    raise CorpusIOError(f"file exceeds {_MAXIMUM_FILE_BYTES} bytes")
                if len(records) >= _MAXIMUM_RECORDS:
                    raise CorpusIOError(
                        f"record count exceeds {_MAXIMUM_RECORDS}"
                    )
                raw_record = _decode_line(raw_line, line_number)
                try:
                    record = parse_record(raw_record, sources)
                except CanonicalRecordError as exc:
                    raise CorpusIOError(f"line {line_number}: {exc}") from exc
                if expected_kind is not None and record.kind != expected_kind:
                    raise CorpusIOError(
                        f"line {line_number}: expected kind {expected_kind}, got {record.kind}"
                    )
                if record.id in identifiers:
                    raise CorpusIOError(f"duplicate record id: {record.id}")
                identifiers.add(record.id)
                records.append(record)
    except OSError as exc:
        raise CorpusIOError(f"cannot read corpus file: {exc}") from exc
    if not records and not allow_empty:
        raise CorpusIOError("empty corpus is not allowed")
    return tuple(records)


def _encoded_records(
    records: Iterable[CanonicalRecord],
    sources: Mapping[str, SourcePolicy],
    *,
    allow_empty: bool,
) -> tuple[bytes, ...]:
    collected: list[CanonicalRecord] = []
    identifiers: set[str] = set()
    for record in records:
        if len(collected) >= _MAXIMUM_RECORDS:
            raise CorpusIOError(f"record count exceeds {_MAXIMUM_RECORDS}")
        if not isinstance(record, CanonicalRecord):
            raise CorpusIOError("records must contain CanonicalRecord values")
        try:
            validated = parse_record(record_to_mapping(record), sources)
        except (CanonicalRecordError, UnicodeError, AttributeError, TypeError) as exc:
            raise CorpusIOError(str(exc)) from exc
        if validated.id in identifiers:
            raise CorpusIOError(f"duplicate record id: {validated.id}")
        identifiers.add(validated.id)
        collected.append(validated)
    if not collected and not allow_empty:
        raise CorpusIOError("empty corpus is not allowed")

    lines: list[bytes] = []
    total_bytes = 0
    for record in sorted(collected, key=lambda item: (item.kind, item.id)):
        line = (
            json.dumps(
                record_to_mapping(record),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
        if len(line) > _MAXIMUM_LINE_BYTES:
            raise CorpusIOError(
                f"encoded line exceeds {_MAXIMUM_LINE_BYTES} bytes: {record.id}"
            )
        total_bytes += len(line)
        if total_bytes > _MAXIMUM_FILE_BYTES:
            raise CorpusIOError(f"encoded file exceeds {_MAXIMUM_FILE_BYTES} bytes")
        lines.append(line)
    return tuple(lines)


def write_jsonl(
    path: Path,
    records: Iterable[CanonicalRecord],
    sources: Mapping[str, SourcePolicy],
    *,
    allow_empty: bool = False,
) -> None:
    lines = _encoded_records(records, sources, allow_empty=allow_empty)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CorpusIOError(f"cannot create corpus directory: {exc}") from exc

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            for line in lines:
                stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_path, 0o644)
        os.replace(temporary_path, path)
        temporary_path = None
    except OSError as exc:
        raise CorpusIOError(f"cannot atomically write corpus file: {exc}") from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
