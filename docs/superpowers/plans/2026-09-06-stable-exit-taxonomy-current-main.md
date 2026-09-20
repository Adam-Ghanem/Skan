# Stable Process Exit Taxonomy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Skan stable `0/1/2/3/4` process semantics so scripts can distinguish success, bad invocation, capability failure, and runtime failure without changing scan evidence.

**Architecture:** Define one small public exit enum in `core`, map subsystem-specific statuses into `core::StatusCode`, and make the CLI consume those mappings instead of flattening every failure to `EXIT_FAILURE`. Keep `4` reserved; do not invent partial-success behavior. Preserve existing direct CLI validation branches as usage failures where they already represent invalid invocation.

**Tech Stack:** C++20, GNU Make, Bash integration tests, GitHub Actions Linux CI.

**Spec:** `docs/superpowers/specs/2026-09-06-stable-exit-taxonomy.md`

## Global Constraints

- Exit `0` = success.
- Exit `1` = usage / invalid input.
- Exit `2` = permission / capability.
- Exit `3` = runtime / I/O / environmental/internal failure.
- Exit `4` is reserved and MUST NOT be emitted in this slice.
- `ParseError` maps to runtime, not usage.
- `RoutingUnavailable` maps to runtime, not permission.
- Do not add raw-to-connect fallback.
- Do not alter scan evidence, output schemas, service detection, OS detection, or scan methods.
- Do not add a CI test that depends on the hosted runner lacking `CAP_NET_RAW`.

---

### Task 1: Core exit-code contract

**Files:**
- Modify: `include/core/status.hpp`
- Modify: `src/core/status.cpp`
- Modify: `tests/unit/core/test_status.cpp`

**Interfaces:**
- Consumes: existing `core::StatusCode`.
- Produces: `core::ExitCode`, `core::status_to_exit_code(StatusCode)`, `core::exit_code_value(ExitCode)`.

- [ ] **Step 1: Write the failing test**

Add exact public values and mapping assertions to `tests/unit/core/test_status.cpp`:

```cpp
using skan::core::ExitCode;
using skan::core::StatusCode;
using skan::core::exit_code_value;
using skan::core::status_to_exit_code;

assert(exit_code_value(ExitCode::Success) == 0);
assert(exit_code_value(ExitCode::Usage) == 1);
assert(exit_code_value(ExitCode::Permission) == 2);
assert(exit_code_value(ExitCode::Runtime) == 3);
assert(exit_code_value(ExitCode::Partial) == 4);

assert(status_to_exit_code(StatusCode::Ok) == ExitCode::Success);
assert(status_to_exit_code(StatusCode::InvalidArgument) == ExitCode::Usage);
assert(status_to_exit_code(StatusCode::PermissionDenied) == ExitCode::Permission);
assert(status_to_exit_code(StatusCode::MemoryError) == ExitCode::Runtime);
assert(status_to_exit_code(StatusCode::IoError) == ExitCode::Runtime);
assert(status_to_exit_code(StatusCode::ParseError) == ExitCode::Runtime);
assert(status_to_exit_code(StatusCode::NotFound) == ExitCode::Runtime);
assert(status_to_exit_code(StatusCode::InternalError) == ExitCode::Runtime);
assert(status_to_exit_code(StatusCode::ResourceExhausted) == ExitCode::Runtime);
assert(status_to_exit_code(static_cast<StatusCode>(999)) == ExitCode::Runtime);
```

Declare but do not implement the mapping yet:

```cpp
enum class ExitCode : int {
    Success = 0,
    Usage = 1,
    Permission = 2,
    Runtime = 3,
    Partial = 4
};

ExitCode status_to_exit_code(StatusCode status) noexcept;

constexpr int exit_code_value(ExitCode code) noexcept
{
    return static_cast<int>(code);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run through the ordinary CI `make -j2 test` path. Expected: `test_status` fails to link with undefined `status_to_exit_code`, proving the contract is RED rather than failing for an unrelated compile error.

- [ ] **Step 3: Write minimal implementation**

Add to `src/core/status.cpp`:

```cpp
ExitCode status_to_exit_code(StatusCode status) noexcept
{
    switch (status) {
    case StatusCode::Ok:
        return ExitCode::Success;
    case StatusCode::InvalidArgument:
        return ExitCode::Usage;
    case StatusCode::PermissionDenied:
        return ExitCode::Permission;
    case StatusCode::MemoryError:
    case StatusCode::IoError:
    case StatusCode::ParseError:
    case StatusCode::NotFound:
    case StatusCode::InternalError:
    case StatusCode::ResourceExhausted:
    default:
        return ExitCode::Runtime;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run `make -j2 test` in CI. Expected: `test_status` and the existing suite pass.

- [ ] **Step 5: Commit**

Commit message: `feat(trust): define stable process exit taxonomy`.

---

### Task 2: Interface and raw-network status classification

**Files:**
- Modify: `include/net/interface_types.hpp`
- Modify: `src/net/interface_types.cpp`
- Modify: `tests/unit/net/test_interface_types.cpp`
- Modify: `include/net/network_scan_transport.hpp`
- Modify: `src/net/network_scan_transport.cpp`
- Modify: `tests/unit/net/test_network_scan_transport.cpp`

**Interfaces:**
- Consumes: `core::ExitCode`, `core::status_to_exit_code` from Task 1.
- Produces: `net::interface_status_to_exit_code(InterfaceStatus)`, `net::network_scan_status_to_status_code(NetworkScanStatus)`, `net::network_scan_status_to_exit_code(NetworkScanStatus)`.

- [ ] **Step 1: Write failing interface mapping tests**

Add to `tests/unit/net/test_interface_types.cpp`:

```cpp
using skan::core::ExitCode;
using skan::net::InterfaceStatus;
using skan::net::interface_status_to_exit_code;

assert(interface_status_to_exit_code(InterfaceStatus::Success) == ExitCode::Success);
assert(interface_status_to_exit_code(InterfaceStatus::InvalidName) == ExitCode::Usage);
assert(interface_status_to_exit_code(InterfaceStatus::InterfaceNotFound) == ExitCode::Usage);
assert(interface_status_to_exit_code(InterfaceStatus::PermissionDenied) == ExitCode::Permission);
assert(interface_status_to_exit_code(InterfaceStatus::NotSupported) == ExitCode::Permission);
assert(interface_status_to_exit_code(InterfaceStatus::EnumerationFailed) == ExitCode::Runtime);
assert(interface_status_to_exit_code(InterfaceStatus::RoutingUnavailable) == ExitCode::Runtime);
assert(interface_status_to_exit_code(InterfaceStatus::SystemError) == ExitCode::Runtime);
assert(interface_status_to_exit_code(static_cast<InterfaceStatus>(999)) == ExitCode::Runtime);
```

Declare the function in `include/net/interface_types.hpp`, but do not implement it yet.

- [ ] **Step 2: Run test to verify RED**

Expected: `test_interface_types` link failure on `interface_status_to_exit_code` only.

- [ ] **Step 3: Implement interface mapping**

In `src/net/interface_types.cpp`:

```cpp
core::ExitCode interface_status_to_exit_code(InterfaceStatus status) noexcept
{
    switch (status) {
    case InterfaceStatus::Success:
        return core::ExitCode::Success;
    case InterfaceStatus::InvalidName:
    case InterfaceStatus::InterfaceNotFound:
        return core::ExitCode::Usage;
    case InterfaceStatus::PermissionDenied:
    case InterfaceStatus::NotSupported:
        return core::ExitCode::Permission;
    case InterfaceStatus::EnumerationFailed:
    case InterfaceStatus::RoutingUnavailable:
    case InterfaceStatus::SystemError:
    default:
        return core::ExitCode::Runtime;
    }
}
```

Include `core/status.hpp` from the interface status header.

- [ ] **Step 4: Write failing raw-network mapping tests**

Add to `tests/unit/net/test_network_scan_transport.cpp`:

```cpp
using skan::core::ExitCode;
using skan::core::StatusCode;
using skan::net::NetworkScanStatus;

assert(network_scan_status_to_status_code(NetworkScanStatus::Success) == StatusCode::Ok);
assert(network_scan_status_to_status_code(NetworkScanStatus::InvalidConfiguration) == StatusCode::InvalidArgument);
assert(network_scan_status_to_status_code(NetworkScanStatus::InterfaceNotFound) == StatusCode::InvalidArgument);
assert(network_scan_status_to_status_code(NetworkScanStatus::RoutingUnavailable) == StatusCode::IoError);
assert(network_scan_status_to_status_code(NetworkScanStatus::PermissionDenied) == StatusCode::PermissionDenied);
assert(network_scan_status_to_status_code(NetworkScanStatus::NotSupported) == StatusCode::PermissionDenied);
assert(network_scan_status_to_status_code(NetworkScanStatus::NotOpen) == StatusCode::IoError);
assert(network_scan_status_to_status_code(NetworkScanStatus::SystemError) == StatusCode::IoError);

assert(network_scan_status_to_exit_code(NetworkScanStatus::Success) == ExitCode::Success);
assert(network_scan_status_to_exit_code(NetworkScanStatus::InvalidConfiguration) == ExitCode::Usage);
assert(network_scan_status_to_exit_code(NetworkScanStatus::InterfaceNotFound) == ExitCode::Usage);
assert(network_scan_status_to_exit_code(NetworkScanStatus::RoutingUnavailable) == ExitCode::Runtime);
assert(network_scan_status_to_exit_code(NetworkScanStatus::PermissionDenied) == ExitCode::Permission);
assert(network_scan_status_to_exit_code(NetworkScanStatus::NotSupported) == ExitCode::Permission);
assert(network_scan_status_to_exit_code(NetworkScanStatus::NotOpen) == ExitCode::Runtime);
assert(network_scan_status_to_exit_code(NetworkScanStatus::SystemError) == ExitCode::Runtime);
```

Declare the two converters in `include/net/network_scan_transport.hpp`, but leave the old private mapping unchanged for RED.

- [ ] **Step 5: Run tests to verify RED**

Expected: the raw-network mapping test fails to link or fails specifically on `RoutingUnavailable`, not on unrelated network behavior.

- [ ] **Step 6: Implement canonical raw mapping**

In `include/net/network_scan_transport.hpp` or a focused `.cpp` implementation if linkage is cleaner:

```cpp
core::StatusCode network_scan_status_to_status_code(NetworkScanStatus status) noexcept
{
    switch (status) {
    case NetworkScanStatus::Success:
        return core::StatusCode::Ok;
    case NetworkScanStatus::InvalidConfiguration:
    case NetworkScanStatus::InterfaceNotFound:
        return core::StatusCode::InvalidArgument;
    case NetworkScanStatus::PermissionDenied:
    case NetworkScanStatus::NotSupported:
        return core::StatusCode::PermissionDenied;
    case NetworkScanStatus::RoutingUnavailable:
    case NetworkScanStatus::NotOpen:
    case NetworkScanStatus::SystemError:
    default:
        return core::StatusCode::IoError;
    }
}

core::ExitCode network_scan_status_to_exit_code(NetworkScanStatus status) noexcept
{
    return core::status_to_exit_code(network_scan_status_to_status_code(status));
}
```

Replace the private `map_network_status` behavior in `src/net/network_scan_transport.cpp` with the canonical function so `RoutingUnavailable` no longer becomes `PermissionDenied`.

- [ ] **Step 7: Run focused and full tests**

Expected: interface/raw mapping tests pass; existing raw capability-aware tests preserve their current skip/pass behavior.

- [ ] **Step 8: Commit**

Commit message: `fix(trust): classify network failures consistently`.

---

### Task 3: Make orchestrator consume canonical network status

**Files:**
- Modify: `src/orchestrator/scan_stage.cpp`
- Test: existing orchestrator unit/integration tests; add a focused test only if the existing dependency injection can deterministically return `RoutingUnavailable`.

**Interfaces:**
- Consumes: `net::network_scan_status_to_status_code` from Task 2.
- Produces: one consistent raw transport failure status in discovery/TCP/UDP stages.

- [ ] **Step 1: Add a focused failing test when injection supports it**

Construct a `NetworkScanResult` with `status = RoutingUnavailable` through the existing stage dependency seam and assert the resulting `StageResult.status` is `IoError`. If the seam cannot expose `NetworkScanResult` without restructuring, rely on the Task 2 unit mapping and keep this task to deduplication only; do not introduce a new fake transport abstraction solely for this assertion.

- [ ] **Step 2: Replace the divergent switch**

Change:

```cpp
core::StatusCode network_failure_status(const net::NetworkScanResult &result) noexcept
{
    if (result.status == net::NetworkScanStatus::PermissionDenied ||
        result.status == net::NetworkScanStatus::NotSupported ||
        result.status == net::NetworkScanStatus::RoutingUnavailable) {
        return core::StatusCode::PermissionDenied;
    }
    ...
}
```

To:

```cpp
core::StatusCode network_failure_status(const net::NetworkScanResult &result) noexcept
{
    return net::network_scan_status_to_status_code(result.status);
}
```

- [ ] **Step 3: Run full tests**

Expected: discovery, TCP, UDP, orchestrator, and raw-lab tests preserve behavior except for corrected status classification on no-route failures.

- [ ] **Step 4: Commit**

Commit message: `fix(trust): reuse canonical raw failure mapping`.

---

### Task 4: Wire exact exit codes into the CLI

**Files:**
- Modify: `src/main.cpp`
- Modify: `tests/integration/cli/test_nmap_compat.sh`

**Interfaces:**
- Consumes: `core::exit_code_value`, `core::status_to_exit_code`, interface/raw status converters.
- Produces: observable process exit semantics.

- [ ] **Step 1: Add exact process-level regression helper**

In `tests/integration/cli/test_nmap_compat.sh`, add a helper that captures the real process code without `set -e` swallowing it:

```bash
expect_exit() {
  local expected=$1
  shift
  set +e
  "$@" >/dev/null 2>"$tmp_dir/exit-stderr.txt"
  local actual=$?
  set -e
  if [[ "$actual" -ne "$expected" ]]; then
    echo "expected exit $expected, got $actual: $*" >&2
    cat "$tmp_dir/exit-stderr.txt" >&2 || true
    exit 1
  fi
}
```

Add deterministic checks:

```bash
expect_exit 0 "$skan_bin" -sS --transport offline -p 80 192.0.2.1
expect_exit 1 "$skan_bin" -sS --transport offline -4 -6 -p 80 192.0.2.1
expect_exit 1 "$skan_bin" -sS --transport offline -p 0 192.0.2.1
expect_exit 3 "$skan_bin" -sS --transport offline -p 80 \
  --output-file /proc/skan-exit-taxonomy-impossible 192.0.2.1
```

Do not add a hosted-runner permission assertion here.

- [ ] **Step 2: Run regression and verify RED**

Expected: success/usage checks retain current values, while the deterministic output-file failure returns the legacy flattened `1` instead of required `3`.

- [ ] **Step 3: Audit `src/main.cpp` return paths**

Classify every `return EXIT_FAILURE` before editing:

- parser/conflict/invalid explicit argument -> `Usage`
- `InterfaceResult` failure -> `interface_status_to_exit_code`
- `NetworkScanResult` capability/runtime failure -> `network_scan_status_to_exit_code`
- orchestrator/pipeline `StatusCode` failure -> `status_to_exit_code`
- output/file/runtime failure -> `Runtime`

Do not bulk replace. Each branch must be classified from its actual source.

- [ ] **Step 4: Introduce small CLI helpers**

At file scope:

```cpp
int process_exit(skan::core::ExitCode code) noexcept
{
    return skan::core::exit_code_value(code);
}

int process_exit(skan::core::StatusCode status) noexcept
{
    return process_exit(skan::core::status_to_exit_code(status));
}
```

Use `process_exit(ExitCode::Usage)` for direct invalid invocation and canonical subsystem mappings for structured errors.

- [ ] **Step 5: Run exact process regressions**

Expected: deterministic checks return `0`, `1`, `1`, `3` exactly.

- [ ] **Step 6: Run full CLI compatibility and terminal policy**

Run:

```bash
bash tests/integration/cli/test_nmap_compat.sh
python3 tests/integration/cli/test_terminal_policy.py
```

Expected: PASS with unchanged stdout/stderr content contracts except process codes.

- [ ] **Step 7: Commit**

Commit message: `feat(cli): expose stable failure exit codes`.

---

### Task 5: Document and verify the public contract

**Files:**
- Create: `docs/EXIT_CODES.md`
- Modify: `README.md` only with a short link if needed; do not expand the README substantially.

**Interfaces:**
- Consumes: final verified taxonomy.
- Produces: user-facing automation documentation.

- [ ] **Step 1: Write exact documentation**

Document the `0/1/2/3/4` table from the spec, explicitly state `4` is reserved/not currently emitted, and give shell examples:

```bash
skan -sT -p 443 example.com
case $? in
  0) echo success ;;
  1) echo invalid-invocation ;;
  2) echo missing-capability ;;
  3) echo runtime-failure ;;
  4) echo partial-result ;;
esac
```

- [ ] **Step 2: Run verification gates**

Require current branch CI to pass:

- clean build + complete test target
- Nmap-compatible CLI regression
- terminal policy
- debug/release
- ASan/UBSan/coverage
- fuzz/benchmark
- static/security + packaging harness tests
- privileged IPv4/IPv6 lab
- build-test-audit
- Debian package acceptance

- [ ] **Step 3: Review for taxonomy leaks**

Search remaining `EXIT_FAILURE` uses in `src/main.cpp`. Every remaining occurrence must be justified as usage-only, or replaced with an explicit mapped code.

- [ ] **Step 4: Commit**

Commit message: `docs(cli): document stable exit semantics`.

## Self-review

- Spec coverage: core mapping, interface mapping, raw network mapping, orchestrator deduplication, observable CLI codes, deterministic I/O regression, docs, and full CI are covered.
- No partial-result behavior is fabricated; `4` remains reserved.
- No hosted-runner capability assumption is introduced.
- `ParseError` and `RoutingUnavailable` are explicitly protected against the two semantic mistakes found in the stale PR #14 work.
- The plan does not alter scan evidence, schemas, ACK behavior, or fallback policy.
