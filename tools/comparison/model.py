from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RunStatus(str, Enum):
    COMPLETE = "complete"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    ERROR = "error"
    INVALID = "invalid"


@dataclass(frozen=True, order=True)
class Endpoint:
    target: str
    protocol: str
    port: int


@dataclass(frozen=True)
class Expectation:
    endpoint: Endpoint
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None

    @property
    def port(self) -> int:
        return self.endpoint.port


@dataclass(frozen=True)
class Scenario:
    identifier: str
    target: str
    protocol: str
    timeout_seconds: float
    authorization: str
    expectations: tuple[Expectation, ...]


@dataclass(frozen=True)
class ComparisonManifest:
    schema_version: int
    suite_id: str
    scenarios: tuple[Scenario, ...]

    @property
    def expectation_count(self) -> int:
        return sum(len(scenario.expectations) for scenario in self.scenarios)


@dataclass(frozen=True)
class Observation:
    endpoint: Endpoint
    state: str
    reason: str = ""
    service: str | None = None
    product: str | None = None
    version: str | None = None
    confidence: float | None = None


@dataclass(frozen=True)
class StateSummary:
    target: str
    state: str
    count: int
    reason: str = ""


@dataclass(frozen=True)
class ScannerRun:
    scanner: str
    version: str
    status: RunStatus
    elapsed_seconds: float | None
    observations: tuple[Observation, ...]
    diagnostic: str = ""
    state_summaries: tuple[StateSummary, ...] = ()


@dataclass(frozen=True, order=True)
class BenchmarkScenario:
    scenario_id: str
    profile: str
    condition: str
