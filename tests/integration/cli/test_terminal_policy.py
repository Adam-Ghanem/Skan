#!/usr/bin/env python3
"""PTY policy regression for Skan's interactive terminal output.

All scans use the offline transport and the RFC 5737 documentation range.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import pathlib
import pty
import struct
import subprocess
import tempfile
import termios


ROOT = pathlib.Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="ascii").strip().encode("ascii")
SKAN = pathlib.Path(os.environ.get("SKAN_BIN", ROOT / "bin" / "skan"))
SCAN = [str(SKAN), "-sS", "--transport", "offline", "-p", "80", "--reason", "192.0.2.1"]


def terminal_environment(**updates: str | None) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update({"TERM": "xterm-256color", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    environment.pop("NO_COLOR", None)
    for key, value in updates.items():
        if value is None:
            environment.pop(key, None)
        else:
            environment[key] = value
    return environment


def run_pty(
    arguments: list[str],
    *,
    environment: dict[str, str] | None = None,
    stdout_path: pathlib.Path | None = None,
) -> tuple[int, bytes]:
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))
    output_file = stdout_path.open("wb") if stdout_path is not None else None
    try:
        process = subprocess.Popen(
            arguments,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=output_file if output_file is not None else slave,
            stderr=slave,
            env=environment or terminal_environment(),
            close_fds=True,
        )
    finally:
        os.close(slave)

    captured = bytearray()
    try:
        while True:
            try:
                chunk = os.read(master, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            captured.extend(chunk)
    finally:
        os.close(master)
        if output_file is not None:
            output_file.close()
    return process.wait(timeout=20), bytes(captured)


def assert_success(result: tuple[int, bytes]) -> bytes:
    status, captured = result
    assert status == 0, captured.decode("utf-8", errors="replace")
    return captured


def main() -> None:
    hostile_target = "bad\x1b]0;owned\x07"
    status, rejected = run_pty([str(SKAN), "resolve", hostile_target])
    assert status != 0
    assert b"invalid hostname" in rejected
    assert b"\x1b" not in rejected and b"\x07" not in rejected

    hostile_interface = "missing\x1b]0;owned\x07"
    status, rejected = run_pty([str(SKAN), "interfaces", "--interface", hostile_interface])
    assert status != 0
    assert b"interface was not found" in rejected
    assert b"\x1b" not in rejected and b"\x07" not in rejected

    interactive = assert_success(run_pty(SCAN))
    assert b"\x1b[2K" in interactive
    assert "◈ SKAN".encode() in interactive
    assert b"\x1b[36;1m" in interactive
    assert b"ETA" not in interactive and b"/s" not in interactive

    no_color = assert_success(run_pty(SCAN + ["--no-color"]))
    assert b"\x1b[2K" in no_color
    assert b"\x1b[36;1m" not in no_color

    no_color_environment = assert_success(run_pty(SCAN, environment=terminal_environment(NO_COLOR="1")))
    assert b"\x1b[2K" in no_color_environment
    assert b"\x1b[36;1m" not in no_color_environment

    dumb = assert_success(run_pty(SCAN, environment=terminal_environment(TERM="dumb")))
    assert b"\x1b" not in dumb
    assert dumb.startswith(b"SKAN v" + VERSION + b"\r\n")
    assert "◈".encode() not in dumb

    debug = assert_success(run_pty(SCAN + ["--debug"]))
    assert b"\x1b[2K" not in debug
    assert b"SKAN" in debug

    with tempfile.TemporaryDirectory(prefix="skan-terminal-policy-") as directory:
        temporary = pathlib.Path(directory)
        redirected_path = temporary / "redirected.nmap"
        redirected_stderr = assert_success(run_pty(SCAN, stdout_path=redirected_path))
        redirected = redirected_path.read_bytes()
        assert redirected_stderr == b""
        assert redirected.startswith(b"SKAN v" + VERSION + b"\n")
        assert b"\x1b" not in redirected and "◈".encode() not in redirected

        output_path = temporary / "file.nmap"
        file_stderr = assert_success(run_pty(SCAN + ["-oN", str(output_path)]))
        file_output = output_path.read_bytes()
        assert file_stderr == b""
        assert file_output.startswith(b"SKAN v" + VERSION + b"\n")
        assert b"\x1b" not in file_output

    machine = assert_success(run_pty(SCAN + ["--output", "json"]))
    assert b"\x1b" not in machine
    json.loads(machine.decode("utf-8"))


if __name__ == "__main__":
    main()
