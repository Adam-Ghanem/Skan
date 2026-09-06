# Skan process exit codes

Skan exposes stable process exit codes so shell scripts, CI jobs, and automation can distinguish caller mistakes from capability and runtime failures.

| Exit code | Meaning | Typical examples |
| ---: | --- | --- |
| `0` | Success | The requested operation completed successfully. |
| `1` | Usage / invalid input | Unknown or conflicting options, invalid target syntax, invalid port selection, or an explicitly named interface that does not exist. |
| `2` | Permission / capability | A requested raw-packet operation cannot obtain the required permission or platform capability. |
| `3` | Runtime / I/O / environment | Routing unavailable, DNS resolution failure, output-file I/O failure, missing runtime data, parse failure in runtime data, resource exhaustion, or an internal/runtime error. |
| `4` | Reserved for future partial-result semantics | **Not currently emitted.** Skan does not invent partial-success behavior in the current release. |

## Examples

```bash
skan -sT -p 443 example.com
case $? in
  0) echo "scan completed" ;;
  1) echo "invalid invocation" ;;
  2) echo "permission or capability unavailable" ;;
  3) echo "runtime or environment failure" ;;
  4) echo "reserved; not emitted by the current release" ;;
esac
```

A raw scan that lacks the required packet capability is a capability failure, not a usage error:

```bash
skan -sS --transport linux --interface eth0 -p 443 192.0.2.10
status=$?
if [ "$status" -eq 2 ]; then
  echo "raw-packet capability unavailable"
fi
```

An output destination that cannot be opened or written is a runtime/I/O failure:

```bash
skan -sT -p 443 --output json --output-file /unwritable/result.json 192.0.2.10
# exits 3 when the output path cannot be opened or written
```

## Classification rules

Skan first preserves subsystem evidence, then maps it through the canonical internal status taxonomy. In particular:

- `ParseError` is a runtime failure (`3`), because it represents parsing of runtime/project data rather than CLI syntax.
- `RoutingUnavailable` is a runtime/environment failure (`3`), not a permission failure.
- Invalid CLI syntax and caller-selected invalid values remain usage failures (`1`).
- Explicit permission/capability failures remain `2`; Skan does not silently fall back from a requested raw scan to another scan method.
- Exit `4` remains reserved until Skan has a real, documented partial-result contract.

Skan does not install a custom signal-to-exit remapping for this taxonomy. Normal operating-system signal termination therefore keeps native shell signal semantics rather than being rewritten as one of `0`–`4`.
