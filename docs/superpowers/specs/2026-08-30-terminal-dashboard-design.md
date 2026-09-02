# Skan responsive terminal dashboard design

**Status:** Approved for autonomous implementation

## Purpose

Skan's interactive normal output will become a responsive, professional terminal dashboard while preserving stable, decoration-free behavior for files, pipes, CI, JSON, XML, and grepable output. The dashboard is a streaming terminal presentation layer over the existing canonical `ScanReport`; it is not a second result model and not a full-screen terminal application.

## Trust and compatibility boundaries

- Terminal decoration is enabled only for normal output written directly to an interactive terminal.
- Redirected output, output files, aggregate `-oA` files, `TERM=dumb`, and non-interactive execution use the plain normal renderer.
- JSON, XML, and grepable writers remain byte-compatible and never receive terminal escape sequences.
- `--no-color` and the `NO_COLOR` environment convention disable color. Unicode line drawing is independent of color and requires a compatible interactive locale.
- Network-derived and user-controlled text is sanitized before terminal rendering. Control bytes, including ESC, cannot become terminal commands.
- Diagnostic logs remain on stderr and are controlled by an explicit logging policy; the renderer never mutates the process environment.

## Architecture

`TerminalCapabilities` is detected once at the CLI boundary. It records interactivity, terminal width, Unicode support, and color support. Detection uses POSIX terminal facilities behind a small interface so tests can construct capabilities without a real terminal.

`TerminalLayout` maps capabilities to four deterministic modes:

- Wide: 120 columns or more. Full brand header and side-by-side summary where content permits.
- Medium: 88–119 columns. Compact wordmark and summary below results.
- Narrow: 64–87 columns. Reduced columns and wrapped details.
- Plain: below 64 columns or any non-interactive/unsupported terminal. Stable ASCII lines without borders, icons, progress repainting, or ANSI.

`TerminalTheme` owns fixed semantic styles for brand, metadata, open, filtered, closed/error, warning, and success. Width calculations operate on unstyled text. Styling is applied only after padding and truncation.

The interactive normal renderer is composed from:

- `HeaderRenderer`
- `HostRenderer`
- `PortTableRenderer`
- `SummaryRenderer`
- `FooterRenderer`
- `ProgressRenderer`

These components consume `ScanReport`, `HostResult`, `ScanSummary`, and presentation-only capability/layout values. They do not own scan evidence.

## Rendering behavior

The header uses the Skan brand, version, tagline, target, start time, and available scan metadata. Large logo treatment is restricted to wide terminals; medium uses a wordmark; narrow omits large branding.

Each host has a clear status section. Port tables select columns based on available width:

- Wide: `PORT STATE SERVICE VERSION REASON`
- Medium: `PORT STATE SERVICE VERSION`, with reason in a detail line when requested
- Narrow: `PORT STATE SERVICE`, with version/reason wrapped below
- Plain: stable one-record-per-line compatibility output

Column sizing is based on visible display cells, not ANSI byte length. Long values are bounded with deterministic truncation or wrapping; IPv6 and long service versions cannot push table structure beyond the selected width. Multiple detected service results for one endpoint are rendered deterministically rather than silently discarded.

The summary reports only values derived from the canonical report. The footer ends with `Skan — See more. Know more. Secure more.` in interactive modes.

## Progress behavior

`ProgressRenderer` consumes real orchestration events and configured work totals. It never invents values. On an interactive terminal it may repaint one stderr line containing completed/total work, elapsed time, rate, and ETA only when those values are computable. Non-interactive runs emit no progress line. A final render clears the transient line before normal report output.

The current engine publishes some completion events after a stage returns. The dashboard may therefore update in truthful batches until a later progress/resume phase introduces finer-grained live callbacks. It must not claim smooth real-time scheduling that the engine does not expose.

## Testing

Checked-in golden fixtures cover wide, medium, narrow, plain redirect, color disabled, long version strings, IPv6, multiple hosts, no open ports, reasons, multiple services, control-character sanitization, and machine-output non-regression. Capability and layout tests cover `NO_COLOR`, `TERM=dumb`, width boundaries, and Unicode fallback. Progress tests use deterministic timestamps and counters.

The Makefile must execute every registered test binary, including the currently omitted IPv6 and ICMPv6 tests.

## Deferred work

- Cross-platform terminal capability implementations beyond the current Linux target.
- Durable resume state and finer-grained scheduler callbacks.
- Full-screen interaction, keybindings, mouse input, or curses dependencies.
- Traceroute and additional scan families.
