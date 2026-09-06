# Stable Process Exit Taxonomy Spec

## Goal

Give Skan a stable, automation-safe process exit contract that distinguishes bad invocation, missing capability/permission, and runtime failure without changing scan evidence or silently masking errors.

## Public contract

| Exit | Meaning | Examples |
| ---: | --- | --- |
| `0` | Success | scan/resolve/interfaces command completed successfully |
| `1` | Usage / invalid input | unknown option, invalid port, conflicting options, explicitly named interface does not exist |
| `2` | Permission / capability | raw capture/injection unavailable, unsupported raw family/method due capability boundary |
| `3` | Runtime / I/O / environmental failure | routing unavailable, output-file failure, DNS/runtime parser failure, internal/resource failure |
| `4` | Partial result | Reserved only; this slice must not emit `4` until Skan has a real partial-result contract |

OS-level signal termination is outside this 0–4 taxonomy and is not remapped in this slice.

## Internal status mapping

`core::StatusCode` maps as follows:

- `Ok` -> `0`
- `InvalidArgument` -> `1`
- `PermissionDenied` -> `2`
- `MemoryError`, `IoError`, `ParseError`, `NotFound`, `InternalError`, `ResourceExhausted`, unknown -> `3`

`ParseError` is runtime by default because it is used by runtime data/database parsers, not only CLI parsing. CLI syntax/input failures must return usage directly or surface as `InvalidArgument`.

## Interface status mapping

- `Success` -> `0`
- `InvalidName`, `InterfaceNotFound` -> `1`
- `PermissionDenied`, `NotSupported` -> `2`
- `EnumerationFailed`, `RoutingUnavailable`, `SystemError`, unknown -> `3`

## Raw network status mapping

`NetworkScanStatus` must map to an internal `StatusCode` first, then to the process code:

- `Success` -> `Ok` -> `0`
- `InvalidConfiguration`, `InterfaceNotFound` -> `InvalidArgument` -> `1`
- `PermissionDenied`, `NotSupported` -> `PermissionDenied` -> `2`
- `RoutingUnavailable`, `NotOpen`, `SystemError`, unknown -> `IoError` -> `3`

A missing route is not a permission error.

## Orchestrator requirement

Raw transport failures in `scan_stage.cpp` must use the same canonical `NetworkScanStatus -> StatusCode` mapping as the transport layer. Do not duplicate a divergent switch that classifies `RoutingUnavailable` as permission denied.

## CLI requirement

`main.cpp` may keep direct usage validation branches returning `1`, but runtime and capability paths must use the canonical mappings. At minimum, exact process-level regression coverage must prove:

- a successful deterministic offline scan returns `0`
- an invalid invocation returns `1`
- a deterministic output/I/O failure returns `3`

Capability code `2` must be covered by unit mapping and by a capability-controlled integration environment when one is deterministic; do not write a flaky test that assumes the GitHub runner lacks `CAP_NET_RAW`.

## Non-goals

- No partial-result implementation in this slice.
- No signal-handler redesign.
- No scan-method feature work.
- No change to JSON/XML/grepable schemas.
- No silent fallback between raw and connect transports.
