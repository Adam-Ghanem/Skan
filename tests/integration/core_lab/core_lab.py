#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from typing import Iterable

HERE = Path(__file__).resolve().parent
MANIFEST_PATH = HERE / "truth_manifest.json"
SERVER_PATH = HERE / "lab_server.py"


class LabError(RuntimeError):
    pass


def manifest() -> dict[str, object]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run(
    argv: Iterable[str],
    *,
    check: bool = True,
    capture: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        list(argv),
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        env=env,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() if capture and completed.stderr else ""
        raise LabError(f"command failed ({completed.returncode}): {' '.join(argv)} {detail}".strip())
    return completed


def require_authorized_root() -> None:
    data = manifest()
    safety = data["safety"]
    if os.environ.get(safety["authorization_env"]) != safety["authorization_value"]:
        raise LabError(
            "refusing live lab mutation: set SKAN_AUTHORIZED_LAB=1 only in an explicitly authorized private lab"
        )
    if os.geteuid() != 0:
        raise LabError("ground-truth lab setup requires root/CAP_NET_ADMIN")


def topology() -> dict[str, str]:
    return manifest()["topology"]


def namespace_exists(name: str) -> bool:
    result = run(["ip", "netns", "list"], capture=True)
    return any(line.split()[0] == name for line in result.stdout.splitlines() if line.strip())


def interface_exists(name: str) -> bool:
    return run(["ip", "link", "show", "dev", name], check=False).returncode == 0


def kill_namespace_processes(name: str) -> None:
    if not namespace_exists(name):
        return
    pids = run(["ip", "netns", "pids", name], capture=True, check=False).stdout.split()
    for pid in pids:
        run(["kill", "-TERM", pid], check=False)
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        remaining = run(["ip", "netns", "pids", name], capture=True, check=False).stdout.split()
        if not remaining:
            return
        time.sleep(0.05)
    for pid in run(["ip", "netns", "pids", name], capture=True, check=False).stdout.split():
        run(["kill", "-KILL", pid], check=False)


def clear_qdisc() -> None:
    topo = topology()
    run(["tc", "qdisc", "del", "dev", topo["scanner_interface"], "root"], check=False)
    if namespace_exists(topo["namespace"]):
        run(
            ["ip", "netns", "exec", topo["namespace"], "tc", "qdisc", "del", "dev", topo["target_interface"], "root"],
            check=False,
        )


def cleanup() -> None:
    require_authorized_root()
    topo = topology()
    clear_qdisc()
    if namespace_exists(topo["namespace"]):
        kill_namespace_processes(topo["namespace"])
        run(["ip", "netns", "delete", topo["namespace"]], check=False)
    if interface_exists(topo["scanner_interface"]):
        run(["ip", "link", "delete", topo["scanner_interface"]], check=False)


def launch_server(family: str, protocol: str, bind: str, port: int) -> None:
    topo = topology()
    with open(os.devnull, "wb") as devnull:
        subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                topo["namespace"],
                sys.executable,
                str(SERVER_PATH),
                "--family",
                family,
                "--protocol",
                protocol,
                "--bind",
                bind,
                "--port",
                str(port),
            ],
            stdin=subprocess.DEVNULL,
            stdout=devnull,
            stderr=devnull,
            start_new_session=True,
            close_fds=True,
        )


def wait_for_listener(protocol: str, port: int, timeout_seconds: float = 3.0) -> None:
    topo = topology()
    flag = "-ltnH" if protocol == "tcp" else "-lunH"
    deadline = time.monotonic() + timeout_seconds
    pattern = re.compile(rf":{port}\b")
    while time.monotonic() < deadline:
        result = run(["ip", "netns", "exec", topo["namespace"], "ss", flag], capture=True, check=False)
        if pattern.search(result.stdout):
            return
        time.sleep(0.05)
    raise LabError(f"{protocol} listener on port {port} did not become ready")


def prime_neighbor_cache() -> None:
    """Establish direct-link ARP/NDP adjacency without using scanner output as truth."""
    topo = topology()
    interface = topo["scanner_interface"]
    endpoints = (
        (socket.AF_INET, topo["ipv4_target"].split("/")[0], 18080),
        (socket.AF_INET6, topo["ipv6_target"].split("/")[0], 18081),
    )
    for family, address, port in endpoints:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            endpoint = (address, port) if family == socket.AF_INET else (address, port, 0, 0)
            try:
                sock.connect(endpoint)
            except OSError as exc:
                raise LabError(f"failed to establish L2 adjacency for {address}: {exc}") from exc

        result = run(["ip", "neigh", "show", "to", address, "dev", interface], capture=True, check=False)
        normalized = result.stdout.upper()
        if result.returncode != 0 or "LLADDR" not in normalized or "FAILED" in normalized or "INCOMPLETE" in normalized:
            raise LabError(
                f"neighbor resolution for {address} on {interface} is not usable: "
                f"{result.stdout.strip() or result.stderr.strip() or 'no neighbor entry'}"
            )


def configure_firewall() -> None:
    topo = topology()
    ns = topo["namespace"]

    v4_rules = [
        ["-A", "INPUT", "-i", topo["target_interface"], "-p", "tcp", "--dport", "18083", "-j", "DROP"],
        [
            "-A", "INPUT", "-i", topo["target_interface"], "-p", "tcp", "--dport", "18084",
            "-j", "REJECT", "--reject-with", "icmp-admin-prohibited",
        ],
        [
            "-A", "INPUT", "-i", topo["target_interface"], "-p", "tcp", "--dport", "18085",
            "-m", "limit", "--limit", "2/second", "--limit-burst", "1",
            "-j", "REJECT", "--reject-with", "tcp-reset",
        ],
        ["-A", "INPUT", "-i", topo["target_interface"], "-p", "tcp", "--dport", "18085", "-j", "DROP"],
        [
            "-A", "INPUT", "-i", topo["target_interface"], "-p", "tcp", "--dport", "18086",
            "-m", "limit", "--limit", "1/second", "--limit-burst", "1",
            "-j", "REJECT", "--reject-with", "icmp-admin-prohibited",
        ],
        ["-A", "INPUT", "-i", topo["target_interface"], "-p", "tcp", "--dport", "18086", "-j", "DROP"],
    ]
    v6_rules = [
        ["-A", "INPUT", "-i", topo["target_interface"], "-p", "tcp", "--dport", "18083", "-j", "DROP"],
        [
            "-A", "INPUT", "-i", topo["target_interface"], "-p", "tcp", "--dport", "18084",
            "-j", "REJECT", "--reject-with", "icmp6-adm-prohibited",
        ],
        [
            "-A", "INPUT", "-i", topo["target_interface"], "-p", "tcp", "--dport", "18085",
            "-m", "limit", "--limit", "2/second", "--limit-burst", "1",
            "-j", "REJECT", "--reject-with", "tcp-reset",
        ],
        ["-A", "INPUT", "-i", topo["target_interface"], "-p", "tcp", "--dport", "18085", "-j", "DROP"],
        [
            "-A", "INPUT", "-i", topo["target_interface"], "-p", "tcp", "--dport", "18086",
            "-m", "limit", "--limit", "1/second", "--limit-burst", "1",
            "-j", "REJECT", "--reject-with", "icmp6-adm-prohibited",
        ],
        ["-A", "INPUT", "-i", topo["target_interface"], "-p", "tcp", "--dport", "18086", "-j", "DROP"],
    ]

    for rule in v4_rules:
        run(["ip", "netns", "exec", ns, "iptables", *rule])
    for rule in v6_rules:
        run(["ip", "netns", "exec", ns, "ip6tables", *rule])


def setup() -> None:
    require_authorized_root()
    required = ("ip", "tc", "ss", "iptables", "ip6tables")
    missing = [name for name in required if not command_exists(name)]
    if missing:
        raise LabError("missing lab tools: " + ", ".join(missing))

    topo = topology()
    if namespace_exists(topo["namespace"]) or interface_exists(topo["scanner_interface"]):
        cleanup()

    run(["ip", "netns", "add", topo["namespace"]])
    try:
        run(["ip", "link", "add", topo["scanner_interface"], "type", "veth", "peer", "name", topo["target_interface"]])
        run(["ip", "link", "set", topo["target_interface"], "netns", topo["namespace"]])
        run(["ip", "address", "add", topo["ipv4_scanner"], "dev", topo["scanner_interface"]])
        run(["ip", "-6", "address", "add", topo["ipv6_scanner"], "dev", topo["scanner_interface"], "nodad"])
        run(["ip", "link", "set", topo["scanner_interface"], "up"])

        run(["ip", "netns", "exec", topo["namespace"], "ip", "link", "set", "lo", "up"])
        run([
            "ip", "netns", "exec", topo["namespace"], "ip", "address", "add",
            topo["ipv4_target"], "dev", topo["target_interface"],
        ])
        run([
            "ip", "netns", "exec", topo["namespace"], "ip", "-6", "address", "add",
            topo["ipv6_target"], "dev", topo["target_interface"], "nodad",
        ])
        run(["ip", "netns", "exec", topo["namespace"], "ip", "link", "set", topo["target_interface"], "up"])

        if command_exists("ethtool"):
            run(["ethtool", "-K", topo["scanner_interface"], "tx", "off", "rx", "off", "tso", "off", "gso", "off", "gro", "off"], check=False)
            run([
                "ip", "netns", "exec", topo["namespace"], "ethtool", "-K", topo["target_interface"],
                "tx", "off", "rx", "off", "tso", "off", "gso", "off", "gro", "off",
            ], check=False)

        launch_server("ipv4", "tcp", topo["ipv4_target"].split("/")[0], 18080)
        launch_server("ipv6", "tcp", topo["ipv6_target"].split("/")[0], 18081)
        launch_server("ipv4", "udp", topo["ipv4_target"].split("/")[0], 18090)
        launch_server("ipv6", "udp", topo["ipv6_target"].split("/")[0], 18091)

        wait_for_listener("tcp", 18080)
        wait_for_listener("tcp", 18081)
        wait_for_listener("udp", 18090)
        wait_for_listener("udp", 18091)
        configure_firewall()
        clear_qdisc()
    except Exception:
        cleanup()
        raise


def profile_by_id(identifier: str) -> dict[str, object]:
    for profile in manifest()["network_profiles"]:
        if profile["id"] == identifier:
            return profile
    raise LabError(f"unknown network profile: {identifier}")


def format_ms(value: float) -> str:
    if value < 1.0:
        return f"{value * 1000.0:g}us"
    return f"{value:g}ms"


def netem_arguments(profile: dict[str, object]) -> list[str]:
    kind = profile["kind"]
    if kind == "clean":
        return []

    args: list[str] = []
    seed = profile.get("seed")
    if seed is not None:
        args += ["seed", str(seed)]

    if kind == "loss":
        args += ["loss", "random", f"{profile['loss_percent']:g}%"]
    elif kind == "rtt":
        args += ["delay", format_ms(float(profile["round_trip_ms"]) / 2.0)]
    elif kind == "jitter":
        args += [
            "delay",
            format_ms(float(profile["delay_ms"])),
            format_ms(float(profile["jitter_ms"])),
            "distribution",
            "normal",
        ]
    elif kind == "duplicate":
        args += ["duplicate", f"{profile['duplicate_percent']:g}%"]
    elif kind == "reorder":
        args += [
            "delay",
            format_ms(float(profile["delay_ms"])),
            "reorder",
            f"{profile['reorder_percent']:g}%",
            f"{profile['correlation_percent']:g}%",
        ]
    elif kind == "burst-loss":
        args += [
            "loss",
            "gemodel",
            f"{profile['p']:g}%",
            f"{profile['r']:g}%",
            f"{profile['one_minus_h']:g}%",
            f"{profile['one_minus_k']:g}%",
        ]
    elif kind == "bandwidth":
        args += ["rate", str(profile["rate"])]
    else:
        raise LabError(f"unsupported network profile kind: {kind}")
    return args


def apply_profile(identifier: str) -> None:
    require_authorized_root()
    topo = topology()
    if not namespace_exists(topo["namespace"]) or not interface_exists(topo["scanner_interface"]):
        raise LabError("ground-truth lab is not set up")

    profile = profile_by_id(identifier)
    clear_qdisc()
    args = netem_arguments(profile)
    if not args:
        return

    root = ["tc", "qdisc", "replace", "dev", topo["scanner_interface"], "root", "netem", *args]
    target = [
        "ip", "netns", "exec", topo["namespace"],
        "tc", "qdisc", "replace", "dev", topo["target_interface"], "root", "netem", *args,
    ]
    try:
        run(root)
        run(target)
    except LabError as exc:
        clear_qdisc()
        if "seed" in args:
            raise LabError(
                f"profile {identifier} requires deterministic netem seed support; this host/iproute2 rejected it"
            ) from exc
        raise


def capture_text(argv: list[str]) -> str:
    result = run(argv, capture=True)
    return result.stdout


def build_snapshot(profile: str) -> dict[str, object]:
    topo = topology()
    if not namespace_exists(topo["namespace"]):
        raise LabError("ground-truth lab is not set up")
    return {
        "schema_version": 1,
        "lab_id": manifest()["lab_id"],
        "profile": profile,
        "captured_at_unix_ns": time.time_ns(),
        "truth_manifest": manifest(),
        "observed_truth": {
            "listeners": capture_text(["ip", "netns", "exec", topo["namespace"], "ss", "-H", "-lntup"]),
            "ipv4_firewall": capture_text(["ip", "netns", "exec", topo["namespace"], "iptables-save"]),
            "ipv6_firewall": capture_text(["ip", "netns", "exec", topo["namespace"], "ip6tables-save"]),
            "scanner_qdisc": capture_text(["tc", "-j", "qdisc", "show", "dev", topo["scanner_interface"]]),
            "target_qdisc": capture_text([
                "ip", "netns", "exec", topo["namespace"], "tc", "-j", "qdisc", "show", "dev", topo["target_interface"],
            ]),
            "scanner_neighbors": capture_text(
                ["ip", "neigh", "show", "dev", topo["scanner_interface"]]
            ),
        },
    }


def snapshot(profile: str, output: Path) -> None:
    require_authorized_root()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(build_snapshot(profile), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def assert_output(text: str, port: int, transport: str, state: str) -> None:
    pattern = re.compile(rf"(^|\s){port}/{transport}\s+{re.escape(state)}(\s|$)", re.MULTILINE)
    if not pattern.search(text):
        raise LabError(f"expected {port}/{transport} {state}; scanner output did not contain it")


def scanner_run(skan: Path, args: list[str], output: Path) -> str:
    env = dict(os.environ)
    env["SKAN_AUTHORIZED_LAB"] = "1"
    result = run([str(skan), *args], capture=True, check=False, env=env)
    output.write_text((result.stdout or "") + (result.stderr or ""), encoding="utf-8")
    if result.returncode != 0:
        raise LabError(f"Skan exited {result.returncode}; inspect {output}")
    return (result.stdout or "") + (result.stderr or "")


def smoke(skan: Path, evidence_dir: Path) -> None:
    require_authorized_root()
    if not skan.is_file() or not os.access(skan, os.X_OK):
        raise LabError(f"Skan binary is not executable: {skan}")
    if not command_exists("tcpdump"):
        raise LabError("tcpdump is required for live evidence capture")

    evidence_dir.mkdir(parents=True, exist_ok=True)
    topo = topology()
    pcap = evidence_dir / "packet-evidence.pcap"
    capture = None
    setup()
    try:
        apply_profile("clean")
        # Raw AF_PACKET SYN/ACK scans intentionally consume the kernel's
        # directly-reachable neighbor state; the scanner does not synthesize
        # an ARP/NDP resolution side path. Establish adjacency explicitly as
        # lab setup, then verify it before packet capture starts.
        prime_neighbor_cache()
        snapshot("clean", evidence_dir / "truth-before.json")

        capture = subprocess.Popen(
            ["tcpdump", "-U", "-i", topo["scanner_interface"], "-nn", "-w", str(pcap)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(0.15)

        ipv4 = scanner_run(
            skan,
            ["-Pn", "-sS", "-p", "18080,18082", "--reason", "-e", topo["scanner_interface"], "192.0.2.2"],
            evidence_dir / "syn-ipv4.txt",
        )
        assert_output(ipv4, 18080, "tcp", "OPEN")
        assert_output(ipv4, 18082, "tcp", "CLOSED")

        ipv6 = scanner_run(
            skan,
            ["-Pn", "-sS", "-6", "-p", "18081,18082", "--reason", "-e", topo["scanner_interface"], "2001:db8:42::2"],
            evidence_dir / "syn-ipv6.txt",
        )
        assert_output(ipv6, 18081, "tcp", "OPEN")
        assert_output(ipv6, 18082, "tcp", "CLOSED")

        ack4 = scanner_run(
            skan,
            ["-Pn", "-sA", "-p", "18080,18083,18084", "--reason", "-e", topo["scanner_interface"], "192.0.2.2"],
            evidence_dir / "ack-ipv4.txt",
        )
        assert_output(ack4, 18080, "tcp", "UNFILTERED")
        assert_output(ack4, 18083, "tcp", "FILTERED")
        assert_output(ack4, 18084, "tcp", "FILTERED")

        snapshot("clean", evidence_dir / "truth-after.json")
    finally:
        if capture is not None:
            capture.send_signal(signal.SIGINT)
            try:
                capture.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.wait(timeout=1.0)
        cleanup()


def contract_check() -> None:
    data = manifest()
    required_profiles = {
        "clean", "loss-1", "loss-5", "loss-10", "loss-20",
        "rtt-1", "rtt-20", "rtt-100", "rtt-300", "rtt-800",
        "jitter", "duplicate", "reorder", "burst-loss", "bandwidth-10mbit",
    }
    actual = {item["id"] for item in data["network_profiles"]}
    if actual != required_profiles:
        raise LabError(f"network-profile contract mismatch: {sorted(actual)}")
    if data["safety"]["public_targets_allowed"] is not False:
        raise LabError("public targets must remain disabled")
    if not SERVER_PATH.is_file():
        raise LabError("lab server is missing")


def main() -> int:
    parser = argparse.ArgumentParser(description="Skan Core V3 isolated ground-truth lab")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check-contract")
    sub.add_parser("setup")
    sub.add_parser("cleanup")

    profile_parser = sub.add_parser("profile")
    profile_parser.add_argument("profile")

    snap = sub.add_parser("snapshot")
    snap.add_argument("--profile", default="clean")
    snap.add_argument("--output", required=True, type=Path)

    smoke_parser = sub.add_parser("smoke")
    smoke_parser.add_argument("--skan", required=True, type=Path)
    smoke_parser.add_argument("--evidence-dir", required=True, type=Path)

    args = parser.parse_args()
    try:
        if args.command == "check-contract":
            contract_check()
        elif args.command == "setup":
            setup()
        elif args.command == "cleanup":
            cleanup()
        elif args.command == "profile":
            apply_profile(args.profile)
        elif args.command == "snapshot":
            snapshot(args.profile, args.output)
        elif args.command == "smoke":
            smoke(args.skan, args.evidence_dir)
        else:
            raise LabError("unsupported command")
    except (LabError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"core-ground-truth-lab: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
