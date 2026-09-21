from __future__ import annotations

import unittest

from tools.comparison.model import (
    ComparisonManifest,
    Endpoint,
    Expectation,
    Observation,
    RunStatus,
    ScannerRun,
    Scenario,
    StateSummary,
)
from tools.comparison.scoring import build_scorecard, score_scanner


def scenario(identifier: str, expectations: tuple[Expectation, ...]) -> Scenario:
    return Scenario(identifier, "127.0.0.1", "tcp", 30.0, "operator-controlled-lab", expectations)


def complete(scanner: str, elapsed: float, observations: tuple[Observation, ...]) -> ScannerRun:
    return ScannerRun(scanner, "1.0", RunStatus.COMPLETE, elapsed, observations)


class ComparisonScoringTests(unittest.TestCase):
    def test_scores_state_confusion_false_open_missing_and_service_evidence(self) -> None:
        endpoints = tuple(Endpoint("127.0.0.1", "tcp", port) for port in (80, 81, 82))
        manifest = ComparisonManifest(
            1,
            "metrics-v1",
            (
                scenario(
                    "states",
                    (
                        Expectation(endpoints[0], "open", "http", "exampled", "1.2"),
                        Expectation(endpoints[1], "closed", "ssh", "openssh", "9.0"),
                        Expectation(endpoints[2], "filtered"),
                    ),
                ),
            ),
        )
        run = complete(
            "Skan",
            1.0,
            (
                Observation(endpoints[0], "open", service="http", product="exampled", version="1.2"),
                Observation(endpoints[1], "open", service="smtp", product="postfix", version="3"),
            ),
        )
        metrics = score_scanner(manifest, {"states": run}, "skan")
        self.assertEqual(metrics.expected_endpoints, 3)
        self.assertEqual(metrics.observed_endpoints, 2)
        self.assertEqual(metrics.state_exact, 1)
        self.assertAlmostEqual(metrics.state_accuracy, 1 / 3)
        self.assertEqual(metrics.false_open, 1)
        self.assertEqual(dict(metrics.confusion)[("closed", "open")], 1)
        self.assertEqual(dict(metrics.confusion)[("filtered", "missing")], 1)
        self.assertEqual(metrics.service.eligible, 2)
        self.assertEqual(metrics.service.reported, 2)
        self.assertEqual(metrics.service.exact, 1)
        self.assertEqual(metrics.service.coverage, 1.0)
        self.assertEqual(metrics.service.f1, 0.5)
        self.assertEqual(metrics.product.f1, 0.5)
        self.assertEqual(metrics.version.f1, 0.5)

    def test_excludes_invalid_runs_and_summarizes_complete_timing(self) -> None:
        endpoint = Endpoint("127.0.0.1", "tcp", 80)
        manifest = ComparisonManifest(
            1,
            "timing-v1",
            tuple(scenario(f"s{index}", (Expectation(endpoint, "open"),)) for index in range(4)),
        )
        observation = (Observation(endpoint, "open"),)
        runs = {
            "s0": complete("Skan", 1.0, observation),
            "s1": complete("Skan", 2.0, observation),
            "s2": complete("Skan", 10.0, observation),
            "s3": ScannerRun("Skan", "1.0", RunStatus.INVALID, None, (), "bad output"),
        }
        metrics = score_scanner(manifest, runs, "skan")
        self.assertEqual(metrics.expected_endpoints, 3)
        self.assertEqual(metrics.elapsed_samples, (1.0, 2.0, 10.0))
        self.assertEqual(metrics.median_seconds, 2.0)
        self.assertEqual(metrics.p95_seconds, 10.0)
        self.assertEqual(metrics.excluded, (("s3", "invalid", "bad output"),))

    def test_superiority_claim_fails_closed_when_any_gate_fails(self) -> None:
        endpoint = Endpoint("127.0.0.1", "tcp", 80)
        manifest = ComparisonManifest(
            1,
            "gates-v1",
            (scenario("web", (Expectation(endpoint, "open", "http", "exampled", "1"),)),),
        )
        skan = complete("Skan", 0.5, (Observation(endpoint, "closed"),))
        nmap = complete(
            "Nmap", 1.0, (Observation(endpoint, "open", service="http", product="exampled", version="1"),)
        )
        scorecard = build_scorecard(
            manifest,
            {"skan": {"web": skan}, "nmap": {"web": nmap}},
            {"os": "linux", "lab": "loopback"},
            quality_gates_passed=True,
        )
        self.assertFalse(scorecard.claim_allowed)
        self.assertTrue(any(not gate.passed for gate in scorecard.gates))
        self.assertEqual(scorecard.environment, (("lab", "loopback"), ("os", "linux")))

    def test_expands_exact_nmap_extraport_summary_and_rejects_ambiguous_counts(self) -> None:
        endpoints = tuple(Endpoint("127.0.0.1", "tcp", port) for port in (80, 81, 82))
        manifest = ComparisonManifest(
            1,
            "extraports-v1",
            (scenario("ports", tuple(Expectation(endpoint, "closed") for endpoint in endpoints)),),
        )
        exact = ScannerRun(
            "Nmap",
            "7.95",
            RunStatus.COMPLETE,
            1.0,
            (),
            state_summaries=(StateSummary("127.0.0.1", "closed", 3, "reset"),),
        )
        metrics = score_scanner(manifest, {"ports": exact}, "nmap")
        self.assertEqual(metrics.state_exact, 3)
        self.assertEqual(metrics.observed_endpoints, 3)
        self.assertFalse(metrics.excluded)

        ambiguous = ScannerRun(
            "Nmap",
            "7.95",
            RunStatus.COMPLETE,
            1.0,
            (),
            state_summaries=(StateSummary("127.0.0.1", "closed", 2, "reset"),),
        )
        rejected = score_scanner(manifest, {"ports": ambiguous}, "nmap")
        self.assertEqual(rejected.expected_endpoints, 0)
        self.assertEqual(rejected.excluded[0][1], "invalid")
        self.assertIn("summary count", rejected.excluded[0][2])

        foreign = ScannerRun(
            "Nmap",
            "7.95",
            RunStatus.COMPLETE,
            1.0,
            tuple(Observation(endpoint, "closed") for endpoint in endpoints),
            state_summaries=(StateSummary("127.0.0.2", "open", 1, "syn-ack"),),
        )
        foreign_metrics = score_scanner(manifest, {"ports": foreign}, "nmap")
        self.assertEqual(foreign_metrics.expected_endpoints, 0)
        self.assertIn("undeclared target", foreign_metrics.excluded[0][2])

    def test_rejects_undeclared_observations_instead_of_hiding_false_open(self) -> None:
        expected = Endpoint("127.0.0.1", "tcp", 80)
        undeclared = Endpoint("127.0.0.1", "tcp", 81)
        manifest = ComparisonManifest(
            1,
            "strict-endpoints-v1",
            (scenario("ports", (Expectation(expected, "open"),)),),
        )
        run = complete(
            "Skan",
            1.0,
            (Observation(expected, "open"), Observation(undeclared, "open")),
        )
        metrics = score_scanner(manifest, {"ports": run}, "skan")
        self.assertEqual(metrics.expected_endpoints, 0)
        self.assertEqual(metrics.excluded[0][1], "invalid")
        self.assertIn("undeclared endpoint", metrics.excluded[0][2])

    def test_arbitrary_small_suite_cannot_unlock_a_superiority_claim(self) -> None:
        endpoint = Endpoint("127.0.0.1", "tcp", 80)
        manifest = ComparisonManifest(
            1,
            "too-small-v1",
            (scenario("web", (Expectation(endpoint, "open", "http", version="1"),)),),
        )
        skan = complete(
            "Skan", 0.5, (Observation(endpoint, "open", service="http", version="1"),)
        )
        nmap = complete("Nmap", 1.0, (Observation(endpoint, "open"),))
        scorecard = build_scorecard(
            manifest,
            {"skan": {"web": skan}, "nmap": {"web": nmap}},
            {},
            quality_gates_passed=True,
        )
        self.assertFalse(scorecard.claim_allowed)
        profile_gate = next(gate for gate in scorecard.gates if gate.name == "Required benchmark profiles")
        self.assertFalse(profile_gate.passed)


if __name__ == "__main__":
    unittest.main()
