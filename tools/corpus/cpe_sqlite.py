from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Iterable

from tools.corpus.adapters.common import AdapterContext
from tools.corpus.adapters.nvd_cpe import parse_cpe23_name, parse_nvd_cpe_json


def _references(record) -> tuple[str, ...]:
    prefix = "reference:"
    return tuple(sorted({
        value[len(prefix):]
        for value in record.evidence_requirements
        if value.startswith(prefix) and value[len(prefix):].strip()
    }))


def build_cpe_sqlite(
    json_paths: Iterable[Path],
    output_path: Path,
    context: AdapterContext,
) -> dict[str, object]:
    paths = sorted((Path(path) for path in json_paths), key=lambda path: str(path))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()
    db = sqlite3.connect(output_path)
    try:
        db.execute("PRAGMA journal_mode=OFF")
        db.execute("PRAGMA synchronous=OFF")
        db.execute("PRAGMA temp_store=MEMORY")
        db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute(
            "CREATE TABLE cpe ("
            "cpe TEXT PRIMARY KEY, part TEXT, vendor TEXT, product TEXT, version TEXT, "
            "update_value TEXT, edition TEXT, language TEXT, sw_edition TEXT, target_sw TEXT, "
            "target_hw TEXT, other TEXT, status TEXT NOT NULL, title TEXT NOT NULL, "
            "references_json TEXT NOT NULL)"
        )
        db.execute(
            "INSERT INTO meta(key,value) VALUES('source_id',?),('revision',?),('source_hash',?)",
            (context.source_id, context.revision, context.source_hash),
        )
        count = 0
        for path in paths:
            records = parse_nvd_cpe_json(path.read_text(encoding="utf-8"), context)
            cpe_records = sorted(
                (record for record in records if record.kind == "cpe_record"),
                key=lambda record: record.cpe[0],
            )
            for record in cpe_records:
                cpe = record.cpe[0]
                identity = parse_cpe23_name(cpe)
                references_json = json.dumps(
                    list(_references(record)),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                db.execute(
                    "INSERT OR REPLACE INTO cpe("
                    "cpe,part,vendor,product,version,update_value,edition,language,sw_edition,"
                    "target_sw,target_hw,other,status,title,references_json"
                    ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        cpe,
                        identity.part,
                        identity.vendor,
                        identity.product,
                        identity.version,
                        identity.update,
                        identity.edition,
                        identity.language,
                        identity.sw_edition,
                        identity.target_sw,
                        identity.target_hw,
                        identity.other,
                        record.status,
                        record.notes,
                        references_json,
                    ),
                )
                count += 1
            db.commit()
        db.execute("CREATE INDEX idx_cpe_identity ON cpe(vendor, product, version)")
        db.execute("CREATE INDEX idx_cpe_product ON cpe(product)")
        db.execute("CREATE INDEX idx_cpe_target ON cpe(target_sw, target_hw)")
        db.commit()
        db.execute("VACUUM")
    finally:
        db.close()
    return {"cpe_records": count, "sqlite_bytes": output_path.stat().st_size, "chunk_files": len(paths)}
