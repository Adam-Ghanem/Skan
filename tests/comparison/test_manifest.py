from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
import unittest

from tools.comparison.manifest import ManifestError, load_manifest


def valid_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "suite_id": "loopback-services-v1",
        "scenarios": [
            {
                "id": "web-v4",
                "target": "127.0.0.1",
                "protocol": "tcp",
                "timeout_seconds": 30,
                "authorization": "operator-controlled-lab",
                "expectations": [
                    {
                        "port": 8080,
                        "state": "open",
                        "service": "http",
                        "product": "exampled",
                        "version": "1.2.3",
                    },
                    {"port": 8081, "state": "closed"},
                ],
            }
        ],
    }


class ComparisonManifestTests(unittest.TestCase):
    def load(self, document: object):
        with tempfile.TemporaryDirectory(prefix="skan-comparison-manifest-") as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(document, allow_nan=True), encoding="utf-8")
            return load_manifest(path)

    def test_loads_minimal_authorized_literal_ip_scenario(self) -> None:
        manifest = self.load(valid_document())
        self.assertEqual(manifest.schema_version, 1)
        self.assertEqual(manifest.suite_id, "loopback-services-v1")
        self.assertEqual(manifest.scenarios[0].target, "127.0.0.1")
        self.assertEqual(manifest.scenarios[0].expectations[0].service, "http")
        self.assertEqual(manifest.expectation_count, 2)

    def test_rejects_unknown_fields_at_every_level(self) -> None:
        for location in ("root", "scenario", "expectation"):
            document = valid_document()
            if location == "root":
                document["unexpected"] = True
            elif location == "scenario":
                document["scenarios"][0]["unexpected"] = True  # type: ignore[index]
            else:
                document["scenarios"][0]["expectations"][0]["unexpected"] = True  # type: ignore[index]
            with self.subTest(location=location), self.assertRaises(ManifestError):
                self.load(document)

    def test_rejects_duplicate_ids_and_endpoints(self) -> None:
        duplicate_id = valid_document()
        duplicate_id["scenarios"].append(dict(duplicate_id["scenarios"][0]))  # type: ignore[union-attr,index]
        with self.assertRaises(ManifestError):
            self.load(duplicate_id)

        duplicate_endpoint = valid_document()
        duplicate_endpoint["scenarios"][0]["expectations"].append(  # type: ignore[index,union-attr]
            {"port": 8080, "state": "filtered"}
        )
        with self.assertRaises(ManifestError):
            self.load(duplicate_endpoint)

    def test_rejects_non_literal_or_expanding_targets(self) -> None:
        for target in ("localhost", "127.0.0.0/24", "127.0.0.1-127.0.0.2", "fe80::1%eth0"):
            document = valid_document()
            document["scenarios"][0]["target"] = target  # type: ignore[index]
            with self.subTest(target=target), self.assertRaises(ManifestError):
                self.load(document)

    def test_requires_exact_authorization_marker(self) -> None:
        for marker in (None, "yes", "public-internet"):
            document = valid_document()
            scenario = document["scenarios"][0]  # type: ignore[index]
            if marker is None:
                del scenario["authorization"]
            else:
                scenario["authorization"] = marker
            with self.subTest(marker=marker), self.assertRaises(ManifestError):
                self.load(document)

    def test_rejects_invalid_ports_states_and_service_shapes(self) -> None:
        mutations = [
            {"port": 0, "state": "open"},
            {"port": 65536, "state": "open"},
            {"port": True, "state": "open"},
            {"port": 80, "state": "maybe"},
            {"port": 80, "state": "open", "product": "orphan"},
        ]
        for expectation in mutations:
            document = valid_document()
            document["scenarios"][0]["expectations"] = [expectation]  # type: ignore[index]
            with self.subTest(expectation=expectation), self.assertRaises(ManifestError):
                self.load(document)

    def test_rejects_non_finite_timeout_and_excessive_collections(self) -> None:
        for timeout in (math.nan, math.inf, 0, 601):
            document = valid_document()
            document["scenarios"][0]["timeout_seconds"] = timeout  # type: ignore[index]
            with self.subTest(timeout=timeout), self.assertRaises(ManifestError):
                self.load(document)

        document = valid_document()
        scenario = document["scenarios"][0]  # type: ignore[index]
        scenario["expectations"] = [
            {"port": port, "state": "closed"} for port in range(1, 4098)
        ]
        with self.assertRaises(ManifestError):
            self.load(document)

    def test_rejects_oversized_files_before_json_parsing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="skan-comparison-manifest-") as directory:
            path = Path(directory) / "manifest.json"
            path.write_bytes(b" " * ((1 << 20) + 1))
            with self.assertRaisesRegex(ManifestError, "size limit"):
                load_manifest(path)

    def test_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory(prefix="skan-comparison-manifest-") as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(
                '{"schema_version":1,"schema_version":1,"suite_id":"x","scenarios":[]}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ManifestError, "duplicate JSON field"):
                load_manifest(path)


if __name__ == "__main__":
    unittest.main()
