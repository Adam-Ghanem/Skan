# Bounded UDP Database Loading Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make direct and file-backed UDP probe database loading reject inputs larger than 1 MiB without performing an unbounded whole-file read.

**Architecture:** Keep the existing `UDPProbeDatabase` grammar and status API. Enforce one shared byte ceiling at the parser boundary and stream files into a bounded string so direct parsing and file loading have identical size semantics.

**Tech Stack:** C++20, Python 3 standard library, GNU Make, `unittest`

**Spec:** `docs/superpowers/specs/2026-09-20-core-superiority-foundation-design.md`

## Global Constraints

- The maximum accepted UDP database size is exactly `1U << 20U` bytes.
- Missing files continue to return `core::StatusCode::NotFound`.
- Inputs larger than the ceiling return `core::StatusCode::ParseError`.
- Allocation failure returns `core::StatusCode::MemoryError`.
- Read failure returns `core::StatusCode::IoError`.
- Valid existing databases and grammar remain unchanged.
- `load_file` must not use `rdbuf()` whole-file streaming.

## Review Focus

- Exactly 1 MiB must be accepted when it is otherwise valid; 1 MiB plus one byte must be rejected.
- An oversized valid prefix followed only by a comment must still be rejected.
- A short read or stream error must not be misreported as a parse error.
- An absent path must remain `NotFound` rather than becoming `IoError`.
- The bounded loader must not parse or expose a truncated prefix of an oversized file.

---

### Task 1: Pin the bounded loader contract

**Files:**
- Create: `tests/corpus/udp_loader_bounds_probe.cpp`
- Create: `tests/corpus/test_udp_loader_bounds.py`
- Modify: `src/portscan/udp_scan.cpp`

**Interfaces:**
- Consumes: `UDPProbeDatabase::parse(std::string_view, StatusCode&)` and `UDPProbeDatabase::load_file(const std::string&, StatusCode&)`.
- Produces: identical 1 MiB limits for direct and file-backed parsing, preserving the existing public API.

- [x] **Step 1: Write the failing C++ behavior probe**

Create `tests/corpus/udp_loader_bounds_probe.cpp` with a standalone `main` that:

```cpp
constexpr std::size_t kMaximumDatabaseBytes = 1U << 20U;

std::string oversized = "probe DEFAULT 0 generic 512 00\n#";
oversized.append(kMaximumDatabaseBytes, 'x');
StatusCode status = StatusCode::InternalError;
const auto direct = UDPProbeDatabase::parse(oversized, status);
if (status != StatusCode::ParseError || !direct.definitions().empty()) return 1;

status = StatusCode::InternalError;
const auto file = UDPProbeDatabase::load_file(argv[1], status);
if (status != StatusCode::ParseError || !file.definitions().empty()) return 1;

status = StatusCode::InternalError;
const auto valid = UDPProbeDatabase::load_file(argv[2], status);
if (status != StatusCode::Ok || valid.definitions().size() != 1U) return 1;

status = StatusCode::InternalError;
const auto missing = UDPProbeDatabase::load_file(argv[3], status);
if (status != StatusCode::NotFound || !missing.definitions().empty()) return 1;
```

The probe must emit a distinct diagnostic for every failed contract.

- [x] **Step 2: Write the Python test driver**

Create `tests/corpus/test_udp_loader_bounds.py`. It must compile the real
`src/portscan/udp_scan.cpp`, create a valid database, an oversized database,
and a missing path inside a temporary directory, run the behavior probe, and
assert exit code zero. The oversized fixture must contain a valid default rule
followed by enough comment bytes to exceed 1 MiB.

Also assert behaviorally that a direct string of exactly 1 MiB is accepted when
the non-rule bytes are a comment, while the same string plus one byte is
rejected. Do not grep production source text.

- [x] **Step 3: Run the focused test and verify RED**

Run:

```bash
python3 -m unittest tests.corpus.test_udp_loader_bounds -v
```

Expected: FAIL because `UDPProbeDatabase::parse` and `load_file` accept the
oversized input.

- [x] **Step 4: Implement the shared bound**

In `src/portscan/udp_scan.cpp`, add:

```cpp
constexpr std::size_t kMaximumDatabaseBytes = 1U << 20U;
```

At the start of `UDPProbeDatabase::parse`, reject `text.size() >
kMaximumDatabaseBytes` with `ParseError`.

Replace `contents << input.rdbuf()` with bounded chunked reads. Reserve no more
than the ceiling, append only bytes actually read, return `IoError` for a bad
stream, and return `ParseError` as soon as one byte beyond the ceiling is
observed. Catch `std::bad_alloc` and return `MemoryError`.

- [x] **Step 5: Run the focused test and verify GREEN**

Run:

```bash
python3 -m unittest tests.corpus.test_udp_loader_bounds -v
```

Expected: PASS, one test case and all probe contracts satisfied.

- [x] **Step 6: Run UDP and corpus regressions**

Run:

```bash
make -j2 build/test_udp_scan && ./build/test_udp_scan
python3 -m unittest discover -s tests/corpus -p 'test_*.py' -v
```

Expected: both commands exit zero; all registered corpus tests pass.

- [x] **Step 7: Commit**

```bash
git add src/portscan/udp_scan.cpp tests/corpus/test_udp_loader_bounds.py tests/corpus/udp_loader_bounds_probe.cpp
git commit -m "fix: bound UDP database loading"
```
