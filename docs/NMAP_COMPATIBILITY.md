# Nmap-Core Compatibility

Skan provides a scoped compatibility surface for common Nmap workflows while retaining its own architecture, evidence model, and safety boundaries.

## Invocation

Native form:

```bash
skan scan <target-spec> [options]
```

Nmap-style form:

```bash
skan [supported-options] <target-spec>
```

The compatibility form accepts one or more positional target specifications before, between, or after supported options. IPv4, IPv6, CIDR, range, hostname, and comma-separated forms are combined through the existing bounded Target Engine. Resolved targets are deduplicated before scheduling.

## Supported mappings

| Alias | Native Skan mapping | Notes |
| --- | --- | --- |
| `-sT` | `--method connect --transport connect` | Normal nonblocking TCP sockets. |
| `-sS` | `--method syn --transport linux` | Requires usable raw capabilities. |
| `-sU` | `--udp --transport linux` | `-p` selects UDP ports in this mode; `--udp-ports` remains available. |
| `-sn` | discovery enabled, port scan disabled | Uses the explicit Linux transport unless overridden for deterministic offline testing. |
| `-Pn` | discovery disabled | Discovery is already off by default for scan mode. |
| `-sV` | `--service-detect` | Uses prioritized probes, explicit fallbacks, soft/hard matches, and the bounded project-owned corpus. |
| `-O` | `--os-detect` | Reports unavailable when reliable evidence cannot be collected. |
| `-T0`…`-T5` | `--timing T0`…`T5` | Reuses the adaptive timing engine. |
| `-e` | `--interface` | Raw scans may still derive a route-consistent interface when omitted. |
| `-4` / `-6` | address-family filter | Mutually exclusive; applied after bounded resolution. |
| `--exclude SPEC` | resolved-target exclusion | Repeatable and accepts the Target Engine's bounded forms. |
| `--exclude-ports SPEC` | active-protocol port exclusion | Applies to TCP or UDP after `-p`, defaults, or `--top-ports`. |
| `--open` | output-state filter | Emits only `OPEN` and `OPEN_OR_FILTERED` port rows; scan evidence and summary counts are unchanged. |
| `--reason` | normal-output detail | Adds the canonical port-state reason to normal output; structured formats already retain reason fields. |
| `-oN` | normal output file | Replaces the selected file. |
| `-oX` | XML output file | Replaces the selected file. |
| `-oG` | grepable output file | Replaces the selected file. |
| `-oA` | normal + XML + grepable | Writes `.nmap`, `.xml`, and `.gnmap`. |
| `--top-ports N` | first N Skan common TCP ports | Deterministic, TCP-only, and currently bounded to 100. |

`-p` and `-p-` are protocol-aware: TCP is selected by default, while `-sU` makes the same syntax select UDP ports. Ambiguous combinations such as UDP `-p` plus `--udp-ports`, `-p` plus `--top-ports`, or `-4` plus `-6` fail explicitly. IPv4/IPv6 targets, output formats, service/OS databases, timing bounds, and target ceilings remain available.

## Explicit differences

Skan does not claim byte-for-byte output compatibility, Nmap database compatibility, or complete feature parity. The current scope excludes NSE, traceroute, resume files, decoys, spoofing, idle scanning, fragmentation/evasion behavior, Internet-wide automation, and unsupported protocol families.

Service coverage is intentionally smaller than Nmap's. TLS certificate fields are available when the peer exposes parseable unencrypted handshake records; TLS 1.3 certificate messages are encrypted and therefore remain unavailable to the current raw probe. See [Service fingerprinting](SERVICE_FINGERPRINTS.md).

`--open` affects serialized port rows only. It does not skip probes, discard canonical results, or rewrite summary counters. `--reason` is additive in normal output, while JSON, XML, and grepable output continue to expose their existing structured evidence.

Interactive normal output is Skan's own responsive dashboard, not a byte-for-byte Nmap clone. It requires a real stdout TTY and uses terminal-width, locale, `TERM`, `NO_COLOR`, and `--no-color` capability policy. Redirected normal output and `-oN`/`-oA` files remain deterministic ASCII with stable host/port rows. JSON, XML, and grepable output remain terminal-decoration-free and replace invalid UTF-8 before format-specific escaping.

Transient progress is eligible only when both stdout and stderr are TTYs, the selected format is normal, no output file is active, and debug logging is off. It reports completed batch counters only and is cleared before final serialization. Skan currently makes no live rate, percentage, or ETA claim because orchestration completion events are emitted after their stages return.

The Skan top-port corpus is project-owned and is not represented as Nmap's frequency ranking. Fingerprint data must be added with clear provenance and compatible licensing.

## Privileged behavior

`-sS`, `-sU`, and live `-sn` select the Linux raw path. Missing permission, route, source address, neighbor evidence, or interface capability is terminal and visible. Skan does not silently downgrade a raw request to Connect or offline observations.
