from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import statistics
from typing import Mapping

from .model import BenchmarkScenario, ComparisonManifest, Expectation, Observation, RunStatus, ScannerRun


@dataclass(frozen=True)
class EvidenceMetrics:
    eligible: int
    reported: int
    exact: int
    coverage: float
    precision: float
    recall: float
    f1: float


@dataclass(frozen=True)
class RunSample:
    scenario_id: str
    status: str
    scanner: str
    version: str
    elapsed_seconds: float | None
    diagnostic: str


@dataclass(frozen=True)
class ScannerMetrics:
    key: str
    scanner_names: tuple[str, ...]
    versions: tuple[str, ...]
    expected_endpoints: int
    observed_endpoints: int
    state_exact: int
    state_accuracy: float
    false_open: int
    confusion: tuple[tuple[tuple[str, str], int], ...]
    service: EvidenceMetrics
    product: EvidenceMetrics
    version: EvidenceMetrics
    elapsed_samples: tuple[float, ...]
    median_seconds: float | None
    p95_seconds: float | None
    excluded: tuple[tuple[str, str, str], ...]
    runs: tuple[RunSample, ...]


@dataclass(frozen=True)
class GateResult:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class Scorecard:
    suite_id: str
    manifest_sha256: str
    environment: tuple[tuple[str, str], ...]
    scanners: tuple[ScannerMetrics, ...]
    gates: tuple[GateResult, ...]
    claim_allowed: bool
    benchmark_scenarios: tuple[BenchmarkScenario, ...] = ()


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _evidence(counts: list[int]) -> EvidenceMetrics:
    eligible, reported, exact = counts
    precision = _ratio(exact, reported)
    recall = _ratio(exact, eligible)
    f1 = 2.0 * precision * recall / (precision + recall) if precision + recall else 0.0
    return EvidenceMetrics(eligible, reported, exact, _ratio(reported, eligible), precision, recall, f1)


def _observe_evidence(expectation: Expectation, actual: object, field: str, counts: list[int]) -> None:
    expected = getattr(expectation, field)
    if expected is None:
        return
    counts[0] += 1
    observed = getattr(actual, field, None) if actual is not None else None
    if observed is not None:
        counts[1] += 1
        if observed == expected:
            counts[2] += 1


def _p95(samples: tuple[float, ...]) -> float | None:
    if not samples:
        return None
    ordered = sorted(samples)
    index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return ordered[index]


def score_scanner(
    manifest: ComparisonManifest,
    runs: Mapping[str, ScannerRun],
    key: str,
) -> ScannerMetrics:
    expected_endpoints = observed_endpoints = state_exact = false_open = 0
    confusion: dict[tuple[str, str], int] = {}
    service_counts = [0, 0, 0]
    product_counts = [0, 0, 0]
    version_counts = [0, 0, 0]
    samples: list[float] = []
    excluded: list[tuple[str, str, str]] = []
    raw_runs: list[RunSample] = []
    scanner_names: set[str] = set()
    versions: set[str] = set()

    for scenario in manifest.scenarios:
        run = runs.get(scenario.identifier)
        if run is None:
            excluded.append((scenario.identifier, "missing", "no run was supplied"))
            raw_runs.append(RunSample(scenario.identifier, "missing", "", "", None, "no run was supplied"))
            continue
        scanner_names.add(run.scanner)
        versions.add(run.version)
        raw_runs.append(
            RunSample(
                scenario.identifier,
                run.status.value,
                run.scanner,
                run.version,
                run.elapsed_seconds,
                run.diagnostic,
            )
        )
        if run.status != RunStatus.COMPLETE:
            excluded.append((scenario.identifier, run.status.value, run.diagnostic))
            continue
        if run.elapsed_seconds is None or not math.isfinite(run.elapsed_seconds) or run.elapsed_seconds < 0:
            excluded.append((scenario.identifier, "invalid", "elapsed time is missing or invalid"))
            continue
        observations = {observation.endpoint: observation for observation in run.observations}
        if len(observations) != len(run.observations):
            excluded.append((scenario.identifier, "invalid", "duplicate normalized endpoint"))
            continue
        expected_set = {expectation.endpoint for expectation in scenario.expectations}
        unexpected = set(observations) - expected_set
        if unexpected:
            excluded.append(
                (scenario.identifier, "invalid", f"scanner returned {len(unexpected)} undeclared endpoint(s)")
            )
            continue
        foreign_summaries = [
            summary for summary in run.state_summaries if summary.target != scenario.target
        ]
        if foreign_summaries:
            excluded.append(
                (
                    scenario.identifier,
                    "invalid",
                    f"scanner returned {len(foreign_summaries)} state summary item(s) for an undeclared target",
                )
            )
            continue
        missing = [endpoint for endpoint in expected_set if endpoint not in observations]
        summaries = [summary for summary in run.state_summaries if summary.target == scenario.target]
        if summaries:
            if len(summaries) != 1 or summaries[0].count != len(missing):
                excluded.append(
                    (
                        scenario.identifier,
                        "invalid",
                        "Nmap extraports summary count does not exactly match missing endpoints",
                    )
                )
                continue
            summary = summaries[0]
            for endpoint in missing:
                observations[endpoint] = Observation(endpoint, summary.state, summary.reason)
        samples.append(run.elapsed_seconds)
        for expectation in scenario.expectations:
            expected_endpoints += 1
            actual = observations.get(expectation.endpoint)
            actual_state = actual.state if actual is not None else "missing"
            if actual is not None:
                observed_endpoints += 1
            confusion[(expectation.state, actual_state)] = confusion.get((expectation.state, actual_state), 0) + 1
            if actual_state == expectation.state:
                state_exact += 1
            if actual_state == "open" and expectation.state != "open":
                false_open += 1
            _observe_evidence(expectation, actual, "service", service_counts)
            _observe_evidence(expectation, actual, "product", product_counts)
            _observe_evidence(expectation, actual, "version", version_counts)

    elapsed_samples = tuple(samples)
    return ScannerMetrics(
        key=key,
        scanner_names=tuple(sorted(scanner_names)),
        versions=tuple(sorted(versions)),
        expected_endpoints=expected_endpoints,
        observed_endpoints=observed_endpoints,
        state_exact=state_exact,
        state_accuracy=_ratio(state_exact, expected_endpoints),
        false_open=false_open,
        confusion=tuple(sorted(confusion.items())),
        service=_evidence(service_counts),
        product=_evidence(product_counts),
        version=_evidence(version_counts),
        elapsed_samples=elapsed_samples,
        median_seconds=statistics.median(elapsed_samples) if elapsed_samples else None,
        p95_seconds=_p95(elapsed_samples),
        excluded=tuple(excluded),
        runs=tuple(raw_runs),
    )


def manifest_digest(manifest: ComparisonManifest) -> str:
    document = {
        "schema_version": manifest.schema_version,
        "suite_id": manifest.suite_id,
        "scenarios": [
            {
                "id": scenario.identifier,
                "target": scenario.target,
                "protocol": scenario.protocol,
                "timeout_seconds": scenario.timeout_seconds,
                "authorization": scenario.authorization,
                "expectations": [
                    {
                        key: value
                        for key, value in {
                            "port": expectation.port,
                            "state": expectation.state,
                            "service": expectation.service,
                            "product": expectation.product,
                            "version": expectation.version,
                        }.items()
                        if value is not None
                    }
                    for expectation in scenario.expectations
                ],
            }
            for scenario in manifest.scenarios
        ],
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _comparison_gates(
    skan: ScannerMetrics | None,
    nmap: ScannerMetrics | None,
    expected_total: int,
    quality_gates_passed: bool,
) -> tuple[GateResult, ...]:
    comparable = (
        skan is not None
        and nmap is not None
        and not skan.excluded
        and not nmap.excluded
        and skan.expected_endpoints == nmap.expected_endpoints == expected_total
    )
    gates = [
        GateResult("Comparable complete runs", bool(comparable), "both scanners must complete every scenario"),
        GateResult("Quality gates", quality_gates_passed, "unit, sanitizer, fuzz, packaging, and privileged CI gates"),
        GateResult(
            "Required benchmark profiles",
            False,
            "schema v1 does not yet attest per-condition accuracy, a modern-service suite, and top-1000 TCP LAN coverage",
        ),
    ]
    if skan is None or nmap is None:
        gates.extend(
            [
                GateResult("Zero Skan false-open results", False, "missing scanner metrics"),
                GateResult("Port-state accuracy", False, "missing scanner metrics"),
                GateResult("Service and version F1", False, "missing scanner metrics"),
                GateResult("Median speed improvement", False, "missing scanner metrics"),
            ]
        )
        return tuple(gates)
    gates.append(GateResult("Zero Skan false-open results", skan.false_open == 0, f"false_open={skan.false_open}"))
    gates.append(
        GateResult(
            "Port-state accuracy",
            comparable and skan.state_accuracy >= nmap.state_accuracy,
            f"skan={skan.state_accuracy:.6f}, nmap={nmap.state_accuracy:.6f}",
        )
    )
    evidence_passed = (
        comparable
        and skan.service.eligible > 0
        and skan.version.eligible > 0
        and skan.service.f1 > nmap.service.f1
        and skan.version.f1 > nmap.version.f1
    )
    gates.append(
        GateResult(
            "Service and version F1",
            evidence_passed,
            f"service={skan.service.f1:.6f}/{nmap.service.f1:.6f}, version={skan.version.f1:.6f}/{nmap.version.f1:.6f}",
        )
    )
    speed_passed = (
        comparable
        and skan.median_seconds is not None
        and nmap.median_seconds is not None
        and skan.median_seconds <= nmap.median_seconds * 0.8
    )
    gates.append(
        GateResult(
            "Median speed improvement",
            speed_passed,
            f"skan={skan.median_seconds}, nmap={nmap.median_seconds}, required=20%",
        )
    )
    return tuple(gates)


def build_scorecard(
    manifest: ComparisonManifest,
    scanner_runs: Mapping[str, Mapping[str, ScannerRun]],
    environment: Mapping[str, str],
    *,
    quality_gates_passed: bool = False,
    benchmark_scenarios: tuple[BenchmarkScenario, ...] = (),
) -> Scorecard:
    normalized_benchmarks = tuple(sorted(benchmark_scenarios))
    benchmark_ids = [item.scenario_id for item in normalized_benchmarks]
    if len(set(benchmark_ids)) != len(benchmark_ids):
        raise ValueError("benchmark scenario metadata contains duplicate identifiers")
    if normalized_benchmarks and set(benchmark_ids) != {
        scenario.identifier for scenario in manifest.scenarios
    }:
        raise ValueError("benchmark scenario metadata must exactly cover the manifest")
    metrics = tuple(
        score_scanner(manifest, scanner_runs[key], key)
        for key in sorted(scanner_runs)
    )
    by_key = {item.key: item for item in metrics}
    gates = _comparison_gates(
        by_key.get("skan"), by_key.get("nmap"), manifest.expectation_count, quality_gates_passed
    )
    normalized_environment = tuple(sorted((str(key), str(value)) for key, value in environment.items()))
    return Scorecard(
        manifest.suite_id,
        manifest_digest(manifest),
        normalized_environment,
        metrics,
        gates,
        bool(gates) and all(gate.passed for gate in gates),
        normalized_benchmarks,
    )
