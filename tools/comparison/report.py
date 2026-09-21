from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile

from .scoring import EvidenceMetrics, ScannerMetrics, Scorecard


def _markdown_code(value: str) -> str:
    longest = 0
    current = 0
    for character in value:
        if character == "`":
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    delimiter = "`" * (longest + 1)
    if value.startswith(("`", " ")) or value.endswith(("`", " ")):
        return f"{delimiter} {value} {delimiter}"
    return f"{delimiter}{value}{delimiter}"


def _evidence(metric: EvidenceMetrics) -> dict[str, int | float]:
    return {
        "eligible": metric.eligible,
        "reported": metric.reported,
        "exact": metric.exact,
        "coverage": metric.coverage,
        "precision": metric.precision,
        "recall": metric.recall,
        "f1": metric.f1,
    }


def _scanner(metric: ScannerMetrics) -> dict[str, object]:
    return {
        "scanner_names": list(metric.scanner_names),
        "versions": list(metric.versions),
        "port_states": {
            "expected": metric.expected_endpoints,
            "observed": metric.observed_endpoints,
            "exact": metric.state_exact,
            "accuracy": metric.state_accuracy,
            "false_open": metric.false_open,
            "confusion": [
                {"expected": pair[0], "actual": pair[1], "count": count}
                for pair, count in metric.confusion
            ],
        },
        "service": _evidence(metric.service),
        "product": _evidence(metric.product),
        "version": _evidence(metric.version),
        "elapsed_seconds": {
            "samples": list(metric.elapsed_samples),
            "median": metric.median_seconds,
            "p95": metric.p95_seconds,
        },
        "excluded": [
            {"scenario_id": scenario_id, "status": status, "diagnostic": diagnostic}
            for scenario_id, status, diagnostic in metric.excluded
        ],
        "runs": [
            {
                "scenario_id": run.scenario_id,
                "status": run.status,
                "scanner": run.scanner,
                "version": run.version,
                "elapsed_seconds": run.elapsed_seconds,
                "diagnostic": run.diagnostic,
            }
            for run in metric.runs
        ],
    }


def scorecard_document(scorecard: Scorecard) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": 1,
        "suite_id": scorecard.suite_id,
        "manifest_sha256": scorecard.manifest_sha256,
        "environment": dict(scorecard.environment),
        "scanners": {metric.key: _scanner(metric) for metric in scorecard.scanners},
        "superiority": {
            "claim_allowed": scorecard.claim_allowed,
            "gates": [
                {"name": gate.name, "passed": gate.passed, "detail": gate.detail}
                for gate in scorecard.gates
            ],
        },
    }
    if scorecard.benchmark_scenarios:
        document["benchmark_scenarios"] = [
            {
                "scenario_id": item.scenario_id,
                "profile": item.profile,
                "condition": item.condition,
            }
            for item in scorecard.benchmark_scenarios
        ]
    return document


def render_json(scorecard: Scorecard) -> str:
    return json.dumps(scorecard_document(scorecard), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_markdown(scorecard: Scorecard) -> str:
    verdict = "ELIGIBLE" if scorecard.claim_allowed else "NOT ELIGIBLE"
    lines = [
        f"# Scanner Comparison: {scorecard.suite_id}",
        "",
        f"**Superiority claim:** {verdict}",
        "",
        f"Manifest SHA-256: `{scorecard.manifest_sha256}`",
    ]
    if scorecard.benchmark_scenarios:
        lines.extend(
            [
                "",
                "## Benchmark scenarios",
                "",
                "| Scenario | Profile | Condition |",
                "|---|---|---|",
            ]
        )
        for item in scorecard.benchmark_scenarios:
            lines.append(f"| `{item.scenario_id}` | `{item.profile}` | `{item.condition}` |")
    lines.extend(
        [
            "",
            "## Results",
            "",
            "| Scanner | State accuracy | False open | Service F1 | Version F1 | Median (s) | p95 (s) |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for metric in scorecard.scanners:
        median = "n/a" if metric.median_seconds is None else f"{metric.median_seconds:.6f}"
        p95 = "n/a" if metric.p95_seconds is None else f"{metric.p95_seconds:.6f}"
        lines.append(
            f"| {metric.key} | {metric.state_accuracy:.6f} | {metric.false_open} | "
            f"{metric.service.f1:.6f} | {metric.version.f1:.6f} | {median} | {p95} |"
        )
    lines.extend(["", "## Superiority gates", ""])
    for gate in scorecard.gates:
        lines.append(f"- [{'x' if gate.passed else ' '}] {gate.name}: {gate.detail}")
    lines.extend(["", "## Environment", ""])
    for key, value in scorecard.environment:
        lines.append(f"- {key}: {_markdown_code(value)}")
    for metric in scorecard.scanners:
        lines.extend(["", f"## {metric.key} run status", ""])
        if not metric.excluded:
            lines.append("All declared scenarios produced valid comparable results.")
        else:
            for scenario_id, status, diagnostic in metric.excluded:
                lines.append(f"- `{scenario_id}`: {status} — {diagnostic}")
    return "\n".join(lines) + "\n"


def _stage(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
    return temporary_path


def _backup_path(path: Path) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".backup", dir=path.parent)
    os.close(descriptor)
    backup = Path(name)
    backup.unlink()
    return backup


def _sync_directories(paths: set[Path]) -> None:
    for directory in paths:
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def write_reports(scorecard: Scorecard, json_path: str | Path, markdown_path: str | Path) -> None:
    json_target = Path(json_path)
    markdown_target = Path(markdown_path)
    if json_target.resolve(strict=False) == markdown_target.resolve(strict=False):
        raise ValueError("JSON and Markdown report paths must be distinct")
    staged: list[Path] = []
    backups: dict[Path, Path] = {}
    installed: list[Path] = []
    targets = (json_target, markdown_target)
    committed = False
    try:
        staged.append(_stage(json_target, render_json(scorecard)))
        staged.append(_stage(markdown_target, render_markdown(scorecard)))
        for target in targets:
            if target.exists() or target.is_symlink():
                backup = _backup_path(target)
                os.replace(target, backup)
                backups[target] = backup
        for source, target in zip(staged, targets, strict=True):
            os.replace(source, target)
            installed.append(target)
        _sync_directories({target.parent for target in targets})
        committed = True
    except BaseException as error:
        rollback_errors: list[str] = []
        for target in reversed(installed):
            if target not in backups:
                try:
                    target.unlink(missing_ok=True)
                except OSError as rollback_error:
                    rollback_errors.append(f"could not remove new {target}: {rollback_error}")
        for target in reversed(targets):
            backup = backups.get(target)
            if backup is not None and backup.exists():
                try:
                    os.replace(backup, target)
                except OSError as rollback_error:
                    rollback_errors.append(
                        f"could not restore {target}; original preserved at {backup}: {rollback_error}"
                    )
        try:
            _sync_directories({target.parent for target in targets})
        except OSError as rollback_error:
            rollback_errors.append(f"could not sync rollback directories: {rollback_error}")
        for message in rollback_errors:
            error.add_note(message)
        raise
    finally:
        for path in staged:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
    if committed:
        for path in backups.values():
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
