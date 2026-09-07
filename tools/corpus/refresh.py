from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from tools.corpus.model import CanonicalRecord
from tools.corpus.source_lock import SourceLock, verify_snapshot


Adapter = Callable[[Path, SourceLock], Iterable[CanonicalRecord]]


@dataclass(frozen=True)
class RefreshResult:
    source_id: str
    revision: str
    record_count: int
    records: tuple[CanonicalRecord, ...]


def refresh_from_snapshot(
    snapshot_path: Path,
    lock: SourceLock,
    adapter: Adapter,
) -> RefreshResult:
    """Verify a pinned local snapshot and adapt it without network access."""
    verify_snapshot(snapshot_path, lock)
    records = tuple(adapter(snapshot_path, lock))
    return RefreshResult(
        source_id=lock.source_id,
        revision=lock.revision,
        record_count=len(records),
        records=records,
    )
