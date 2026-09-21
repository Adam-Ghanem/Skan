from __future__ import annotations

import os
import selectors
import shutil
import signal
import subprocess
import time
from typing import Callable

from .commands import build_nmap_command, build_skan_command
from .model import ComparisonManifest, RunStatus, ScannerRun
from .parsers import MAX_RESULT_BYTES, ResultParseError, parse_nmap_xml, parse_skan_json


MAX_DIAGNOSTIC_BYTES = 4096
MAX_DIAGNOSTIC_CHARACTERS = 4096
MAX_PROCESS_STDERR_BYTES = 4 << 20
Parser = Callable[[bytes], ScannerRun]


def _diagnostic(raw: bytes) -> str:
    truncated = len(raw) > MAX_DIAGNOSTIC_BYTES
    text = raw[:MAX_DIAGNOSTIC_BYTES].decode("utf-8", errors="replace")
    return text + (" …[truncated]" if truncated else "")


def _empty(scanner: str, status: RunStatus, diagnostic: str) -> ScannerRun:
    if len(diagnostic) > MAX_DIAGNOSTIC_CHARACTERS:
        diagnostic = diagnostic[: MAX_DIAGNOSTIC_CHARACTERS - 14] + " …[truncated]"
    return ScannerRun(scanner, "", status, None, (), diagnostic)


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _capture_bounded(
    argv: list[str],
    timeout_seconds: float,
    environment: dict[str, str],
) -> tuple[int, bytes, bytes, tuple[RunStatus, str] | None]:
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        shell=False,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        process.wait()
        raise OSError("failed to create bounded process pipes")

    selector = selectors.DefaultSelector()
    streams = {"stdout": process.stdout, "stderr": process.stderr}
    limits = {"stdout": MAX_RESULT_BYTES, "stderr": MAX_PROCESS_STDERR_BYTES}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    terminal: tuple[RunStatus, str] | None = None
    deadline = time.monotonic() + timeout_seconds
    killed_at: float | None = None
    try:
        for name, stream in streams.items():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            now = time.monotonic()
            if terminal is None and now >= deadline:
                terminal = (RunStatus.TIMEOUT, f"process exceeded {timeout_seconds:g} seconds")
                _kill_process_group(process)
                killed_at = now
            if killed_at is not None and now - killed_at > 1.0:
                for key in list(selector.get_map().values()):
                    selector.unregister(key.fileobj)
                break
            wait = 0.05 if terminal is not None else min(0.05, max(0.0, deadline - now))
            for key, _ in selector.select(wait):
                name = key.data
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer = buffers[name]
                remaining = limits[name] + 1 - len(buffer)
                if remaining > 0:
                    buffer.extend(chunk[:remaining])
                if len(chunk) > remaining or len(buffer) > limits[name]:
                    if terminal is None:
                        terminal = (RunStatus.INVALID, f"scanner {name} exceeds the size limit")
                        _kill_process_group(process)
                        killed_at = time.monotonic()
        try:
            returncode = process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            _kill_process_group(process)
            returncode = process.wait(timeout=1.0)
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]), terminal


def run_command(scanner: str, argv: list[str], timeout_seconds: float, parser: Parser) -> ScannerRun:
    if not argv or shutil.which(argv[0]) is None:
        return _empty(scanner, RunStatus.UNAVAILABLE, f"executable not found: {argv[0] if argv else ''}")
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": "C",
        "LC_ALL": "C",
    }
    try:
        returncode, output, standard_error, terminal = _capture_bounded(argv, timeout_seconds, environment)
    except FileNotFoundError:
        return _empty(scanner, RunStatus.UNAVAILABLE, f"executable not found: {argv[0]}")
    except OSError as error:
        return _empty(scanner, RunStatus.ERROR, f"process launch failed: {error}")
    diagnostic = _diagnostic(standard_error)
    if terminal is not None:
        return _empty(scanner, terminal[0], terminal[1])
    if returncode != 0:
        return _empty(scanner, RunStatus.ERROR, f"exit code {returncode}: {diagnostic}")
    try:
        return parser(output)
    except ResultParseError as error:
        suffix = f"; stderr: {diagnostic}" if diagnostic else ""
        return _empty(scanner, RunStatus.INVALID, f"invalid scanner output: {error}{suffix}")


def run_suite(
    manifest: ComparisonManifest,
    skan_binary: str = "bin/skan",
    nmap_binary: str = "nmap",
) -> dict[str, dict[str, ScannerRun]]:
    results: dict[str, dict[str, ScannerRun]] = {"skan": {}, "nmap": {}}
    for scenario in manifest.scenarios:
        results["skan"][scenario.identifier] = run_command(
            "skan",
            build_skan_command(scenario, skan_binary),
            scenario.timeout_seconds,
            parse_skan_json,
        )
        results["nmap"][scenario.identifier] = run_command(
            "nmap",
            build_nmap_command(scenario, nmap_binary),
            scenario.timeout_seconds,
            parse_nmap_xml,
        )
    return results
