# Skan responsive terminal dashboard implementation plan

> Execute this plan with strict test-first increments. Do not merge until an independent review and fresh full verification pass.

**Goal:** Deliver a responsive, secure interactive CLI dashboard without changing machine-format evidence or redirected normal-output compatibility.

**Architecture:** Detect terminal capabilities once at the CLI boundary, pass presentation state through `OutputContext`, and compose the normal writer from independently tested renderers over the canonical `ScanReport`. Render transient, evidence-backed progress on stderr through the existing orchestration event sink.

**Technology:** C++20, POSIX terminal APIs, GNU Make, existing zero-dependency test executables and shell CLI regression.

---

## Task 1: Reconcile Phase 32 and Phase 33

**Files:** `src/main.cpp`, `include/orchestrator/scan_config.hpp`, `src/orchestrator/scan_pipeline.cpp`, `README.md`, Phase 33 output tests.

1. Merge current `main` and the verified Phase 33 result into the Terminal Identity branch without rewriting published history.
2. Resolve the `src/main.cpp` conflict by retaining target/exclusion selection, `--open`, `--reason`, and terminal controls.
3. Run `git diff --check` and targeted output/CLI regression.
4. Commit the reconciliation separately.

## Task 2: Terminal capabilities and layout

**Create:** `include/output/terminal_capabilities.hpp`, `src/output/terminal_capabilities.cpp`, `include/output/terminal_layout.hpp`, `src/output/terminal_layout.cpp`, `tests/unit/output/test_terminal_capabilities.cpp`, `tests/unit/output/test_terminal_layout.cpp`.

1. Write failing tests for width thresholds, non-TTY plain fallback, `NO_COLOR`, `TERM=dumb`, Unicode fallback, and explicit `--no-color` policy.
2. Run the two test targets and confirm the expected compile/test failures.
3. Implement the smallest capability and layout types that pass.
4. Add sources/targets to `Makefile`; rerun targeted tests.
5. Commit `feat(output): add terminal capability and layout policy`.

## Task 3: Safe theme and display-width helpers

**Create:** `include/output/terminal_theme.hpp`, `src/output/terminal_theme.cpp`, `include/output/terminal_text.hpp`, `src/output/terminal_text.cpp`, plus unit tests.

1. Write failing tests for ANSI-free visible width, deterministic truncation, control-byte sanitization, style-disabled identity behavior, and semantic state colors.
2. Implement fixed theme tokens and bounded text helpers. Apply styling only after layout.
3. Run focused tests and `git diff --check`.
4. Commit `feat(output): add safe terminal text and theme primitives`.

## Task 4: Componentized report rendering

**Create:** renderer headers/sources under `include/output/terminal/` and `src/output/terminal/`; golden fixtures under `tests/data/output/`; tests under `tests/unit/output/`.

1. Add failing byte-exact golden tests for wide, medium, narrow, and plain output.
2. Add edge fixtures for long version values, IPv6, multiple hosts, no open ports, requested reasons, multiple service results, and sanitized controls.
3. Implement header, host, port table, summary, and footer renderers.
4. Make `NormalOutputWriter` select the terminal renderer only for interactive normal output and retain the plain renderer otherwise.
5. Verify every rendered line fits the selected width after removing ANSI sequences.
6. Commit `feat(output): render responsive terminal dashboard`.

## Task 5: CLI policy and truthful progress

**Modify:** `src/main.cpp`, logging API, orchestration integration. **Create:** progress renderer and tests.

1. Write failing CLI/policy tests for `--no-color`, `NO_COLOR`, `TERM=dumb`, redirects, output files, and machine formats.
2. Write deterministic progress tests proving no output for non-TTY and no fabricated rate/ETA when insufficient evidence exists.
3. Replace environment mutation for debug logging with explicit process-local logging configuration.
4. Connect a progress sink only for interactive normal stdout; send transient updates to stderr and clear them before report output.
5. Run targeted unit and CLI regression.
6. Commit `feat(cli): integrate terminal policy and scan progress`.

## Task 6: Test registration, documentation, and compatibility

**Modify:** `Makefile`, `.github/workflows/ci.yml`, `README.md`, `ARCHITECTURE.md`, `NEXT_PHASE_ROADMAP.md`, `docs/NMAP_COMPATIBILITY.md`.

1. Add a failing guard or direct Makefile correction proving `test_ipv6` and `test_icmpv6` execute under `make test`.
2. Document exact TTY/redirect/color behavior and the truthful batched-progress limitation.
3. Keep privileged validation matching semantic port rows rather than decorative bytes.
4. Run machine writer tests to confirm JSON/XML/grepable non-regression.
5. Commit `docs(cli): document responsive terminal output contract`.

## Task 7: Review and verification

1. Request independent code review against the design and current main.
2. Apply only verified review findings using the receiving-code-review workflow.
3. Run fresh: clean build, complete test suite, CLI regression, debug, release, ASan/LSan, UBSan, coverage, benchmark, fuzz, `git diff --check`, and repository-clean validation.
4. Push the Terminal Identity branch, wait for both GitHub Actions jobs, fix failures, and repeat verification.
5. Mark PR ready and squash-merge only when review and CI are green; update local `main` with fast-forward only.
