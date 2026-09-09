from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests.corpus.test_model import (
    SOURCES,
    valid_active_probe_record,
    valid_os_record,
    valid_service_record,
    valid_udp_probe_record,
)
from tools.corpus.io import CorpusIOError, load_jsonl, write_jsonl
from tools.corpus.model import parse_record, stable_record_id


def parsed_service(pattern: str):
    value = valid_service_record()
    value["body"]["pattern"] = pattern  # type: ignore[index]
    value["id"] = stable_record_id(value)
    return parse_record(value, SOURCES)


class CorpusJSONLTests(unittest.TestCase):
    def test_round_trip_is_exact_and_byte_stable(self) -> None:
        records = (parsed_service("^SSH-"), parsed_service("^HTTP/"))
        with tempfile.TemporaryDirectory(prefix="skan-corpus-io-") as directory:
            first = Path(directory) / "first.jsonl"
            second = Path(directory) / "second.jsonl"
            write_jsonl(first, records, SOURCES)
            loaded = load_jsonl(first, SOURCES, expected_kind="service_matcher")
            self.assertEqual(loaded, tuple(sorted(records, key=lambda record: record.id)))
            write_jsonl(second, reversed(records), SOURCES)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertTrue(first.read_bytes().endswith(b"\n"))

    def test_rejects_duplicate_ids_on_read_and_write(self) -> None:
        record = parsed_service("^HTTP/")
        with tempfile.TemporaryDirectory(prefix="skan-corpus-io-") as directory:
            path = Path(directory) / "records.jsonl"
            path.write_bytes(b"preserve-me\n")
            with self.assertRaisesRegex(CorpusIOError, "duplicate record id"):
                write_jsonl(path, (record, record), SOURCES)
            self.assertEqual(path.read_bytes(), b"preserve-me\n")

            valid_path = Path(directory) / "valid.jsonl"
            write_jsonl(valid_path, (record,), SOURCES)
            valid_path.write_bytes(valid_path.read_bytes() * 2)
            with self.assertRaisesRegex(CorpusIOError, "duplicate record id"):
                load_jsonl(valid_path, SOURCES)

    def test_rejects_malformed_utf8_duplicate_json_fields_and_missing_newline(self) -> None:
        record = parsed_service("^HTTP/")
        with tempfile.TemporaryDirectory(prefix="skan-corpus-io-") as directory:
            path = Path(directory) / "records.jsonl"
            path.write_bytes(b"\xff\n")
            with self.assertRaisesRegex(CorpusIOError, "valid UTF-8"):
                load_jsonl(path, SOURCES)

            write_jsonl(path, (record,), SOURCES)
            encoded = path.read_text(encoding="utf-8").rstrip("\n")
            duplicate_id = "{\"id\":\"" + record.id + "\"," + encoded[1:] + "\n"
            path.write_text(duplicate_id, encoding="utf-8", newline="")
            with self.assertRaisesRegex(CorpusIOError, "duplicate JSON field: id"):
                load_jsonl(path, SOURCES)

            write_jsonl(path, (record,), SOURCES)
            path.write_bytes(path.read_bytes().rstrip(b"\n"))
            with self.assertRaisesRegex(CorpusIOError, "must end with LF"):
                load_jsonl(path, SOURCES)

            path.write_bytes(b'{"value":' + (b"9" * 5000) + b"}\n")
            with self.assertRaisesRegex(CorpusIOError, "invalid JSON integer"):
                load_jsonl(path, SOURCES)

            raw = valid_service_record()
            raw["notes"] = "\ud800"
            path.write_text(json.dumps(raw) + "\n", encoding="utf-8", newline="")
            with self.assertRaisesRegex(CorpusIOError, "surrogate"):
                load_jsonl(path, SOURCES)

    def test_enforces_file_line_and_record_limits(self) -> None:
        first = parsed_service("^HTTP/")
        second = parsed_service("^SSH-")
        with tempfile.TemporaryDirectory(prefix="skan-corpus-io-") as directory:
            path = Path(directory) / "records.jsonl"
            path.write_bytes(b"{}\n" * 20)
            with mock.patch("tools.corpus.io._MAXIMUM_FILE_BYTES", 32):
                with self.assertRaisesRegex(CorpusIOError, "file exceeds 32 bytes"):
                    load_jsonl(path, SOURCES)

            path.write_bytes(b"{\"oversized\":true}\n")
            with mock.patch("tools.corpus.io._MAXIMUM_LINE_BYTES", 8):
                with self.assertRaisesRegex(CorpusIOError, "line 1 exceeds 8 bytes"):
                    load_jsonl(path, SOURCES)

            write_jsonl(path, (first, second), SOURCES)
            with mock.patch("tools.corpus.io._MAXIMUM_RECORDS", 1):
                with self.assertRaisesRegex(CorpusIOError, "record count exceeds 1"):
                    load_jsonl(path, SOURCES)

    def test_failed_write_is_atomic(self) -> None:
        record = parsed_service("^HTTP/")
        with tempfile.TemporaryDirectory(prefix="skan-corpus-io-") as directory:
            path = Path(directory) / "records.jsonl"
            path.write_bytes(b"preserve-me\n")
            with mock.patch("tools.corpus.io._MAXIMUM_LINE_BYTES", 64):
                with self.assertRaisesRegex(CorpusIOError, "encoded line exceeds 64 bytes"):
                    write_jsonl(path, (record,), SOURCES)
            self.assertEqual(path.read_bytes(), b"preserve-me\n")
            self.assertEqual(tuple(Path(directory).iterdir()), (path,))

            with mock.patch(
                "tools.corpus.io.os.replace",
                side_effect=OSError("synthetic replace failure"),
            ):
                with self.assertRaisesRegex(CorpusIOError, "cannot atomically write"):
                    write_jsonl(path, (record,), SOURCES)
            self.assertEqual(path.read_bytes(), b"preserve-me\n")
            self.assertEqual(tuple(Path(directory).iterdir()), (path,))

            invalid = replace(record, status="bogus")
            with self.assertRaisesRegex(CorpusIOError, "unsupported status"):
                write_jsonl(path, (invalid,), SOURCES)
            self.assertEqual(path.read_bytes(), b"preserve-me\n")

    def test_kind_enforcement_and_explicit_empty_staging(self) -> None:
        record = parsed_service("^HTTP/")
        with tempfile.TemporaryDirectory(prefix="skan-corpus-io-") as directory:
            path = Path(directory) / "records.jsonl"
            write_jsonl(path, (record,), SOURCES)
            with self.assertRaisesRegex(CorpusIOError, "expected kind os_fingerprint"):
                load_jsonl(path, SOURCES, expected_kind="os_fingerprint")

            empty = Path(directory) / "empty.jsonl"
            write_jsonl(empty, (), SOURCES, allow_empty=True)
            self.assertEqual(load_jsonl(empty, SOURCES, allow_empty=True), ())
            with self.assertRaisesRegex(CorpusIOError, "empty corpus is not allowed"):
                load_jsonl(empty, SOURCES)

    def test_repository_staging_stores_are_explicitly_empty(self) -> None:
        root = Path(__file__).resolve().parents[2]
        expected = {
            "active-probes.jsonl": "active_probe",
            "services.jsonl": "service_matcher",
            "os.jsonl": "os_fingerprint",
            "udp.jsonl": "udp_probe",
        }
        for filename, kind in expected.items():
            with self.subTest(filename=filename):
                path = root / "corpus" / "canonical" / filename
                self.assertEqual(path.read_bytes(), b"")
                self.assertEqual(
                    load_jsonl(path, SOURCES, expected_kind=kind, allow_empty=True),
                    (),
                )

    def test_all_runtime_record_bodies_round_trip(self) -> None:
        raw_records = (
            valid_active_probe_record(),
            valid_service_record(),
            valid_os_record(),
            valid_udp_probe_record(),
        )
        records = tuple(parse_record(value, SOURCES) for value in raw_records)
        with tempfile.TemporaryDirectory(prefix="skan-corpus-io-") as directory:
            path = Path(directory) / "all.jsonl"
            write_jsonl(path, records, SOURCES)
            self.assertEqual(
                load_jsonl(path, SOURCES),
                tuple(sorted(records, key=lambda record: (record.kind, record.id))),
            )

    def test_serialization_does_not_mutate_input(self) -> None:
        value = valid_service_record()
        before = copy.deepcopy(value)
        stable_record_id(value)
        self.assertEqual(value, before)


if __name__ == "__main__":
    unittest.main()
