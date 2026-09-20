from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Iterable

from tools.corpus.adapters.common import AdapterContext
from tools.corpus.adapters.iana_services import parse_iana_csv
from tools.corpus.adapters.recog import parse_recog_xml
from tools.corpus.adapters.wappalyzer import parse_wappalyzer_json
from tools.corpus.attribution import render_notices
from tools.corpus.compile_external import compile_records
from tools.corpus.model import CanonicalRecord
from tools.corpus.sources import SourcePolicy, load_source_manifest


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_directory(path: Path, pattern: str) -> str:
    digest = hashlib.sha256()
    files = sorted(path.rglob(pattern), key=lambda item: item.relative_to(path).as_posix())
    for item in files:
        relative = item.relative_to(path).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        with item.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _context(policy: SourcePolicy, digest: str, *, revision: str | None = None) -> AdapterContext:
    return AdapterContext(
        source_id=policy.id,
        revision=revision or policy.pinned_revision or f"sha256-{digest[:16]}",
        source_url=policy.source_url,
        source_license=policy.license_spdx_or_policy,
        source_hash=f"sha256:{digest}",
    )


def _write_lock(path: Path, context: AdapterContext, adapter: str, attribution: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_id": context.source_id,
                "revision": context.revision,
                "source_url": context.source_url,
                "sha256": context.source_hash.removeprefix("sha256:"),
                "adapter_version": 1,
                "license_policy": context.source_license,
                "attribution": attribution,
            },
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n",
        encoding="utf-8",
    )


def refresh_detection_sources(
    *,
    repo_root: Path,
    recog_dir: Path,
    iana_csv: Path,
    wappalyzer_json: Path,
    output_root: Path,
) -> dict[str, object]:
    sources = load_source_manifest(repo_root / "corpus/sources/sources.json")
    recog_policy = sources["rapid7-recog"]
    iana_policy = sources["iana-services"]
    wapp_policy = sources["wappalyzergo"]

    recog_ctx = _context(recog_policy, _hash_directory(recog_dir, "*.xml"))
    iana_ctx = _context(iana_policy, _hash_file(iana_csv))
    wapp_ctx = _context(wapp_policy, _hash_file(wappalyzer_json))

    records: list[CanonicalRecord] = []
    rejected_recog: list[dict[str, str]] = []
    for path in sorted(recog_dir.rglob("*.xml"), key=lambda item: item.relative_to(recog_dir).as_posix()):
        relative = path.relative_to(recog_dir).as_posix()
        try:
            records.extend(parse_recog_xml(path.read_text(encoding="utf-8"), recog_ctx, source_path=relative))
        except (OSError, UnicodeError, ValueError) as exc:
            rejected_recog.append({"path": relative, "reason": str(exc)})

    records.extend(parse_iana_csv(iana_csv.read_text(encoding="utf-8"), iana_ctx))
    records.extend(parse_wappalyzer_json(wappalyzer_json.read_text(encoding="utf-8"), wapp_ctx))

    canonical_dir = output_root / "canonical"
    compile_summary = compile_records(records, canonical_dir, sources)
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "THIRD_PARTY_NOTICES.md").write_text(render_notices(records, sources), encoding="utf-8")
    locks = output_root / "locks"
    _write_lock(locks / "rapid7-recog.json", recog_ctx, "recog", "Rapid7 Recog")
    _write_lock(locks / "iana-services.json", iana_ctx, "iana_services", "")
    _write_lock(locks / "wappalyzergo.json", wapp_ctx, "wappalyzergo", "ProjectDiscovery WappalyzerGo")

    detection_kinds = {"service_matcher", "active_probe", "os_fingerprint", "udp_probe", "web_fingerprint", "device_fingerprint"}
    detection_records = sum(1 for record in records if record.kind in detection_kinds)
    registry_records = sum(1 for record in records if record.kind == "port_registry")
    summary = {
        **compile_summary,
        "detection_records": detection_records,
        "port_registry_records": registry_records,
        "recog_xml_files": len(list(recog_dir.rglob("*.xml"))),
        "recog_rejected_files": len(rejected_recog),
        "recog_rejections": rejected_recog,
    }
    (output_root / "stats.json").write_text(json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return summary


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build Skan canonical corpus from pinned public source snapshots")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--recog-dir", type=Path, required=True)
    parser.add_argument("--iana-csv", type=Path, required=True)
    parser.add_argument("--wappalyzer-json", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    summary = refresh_detection_sources(
        repo_root=args.repo_root,
        recog_dir=args.recog_dir,
        iana_csv=args.iana_csv,
        wappalyzer_json=args.wappalyzer_json,
        output_root=args.output_root,
    )
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
