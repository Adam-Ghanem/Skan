#!/usr/bin/env python3
from __future__ import annotations

import argparse
import signal
import socket
import sys

RUNNING = True


def stop(_signum: int, _frame: object) -> None:
    global RUNNING
    RUNNING = False


def tcp_server(family: int, bind: str, port: int) -> int:
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind, port))
        sock.listen(32)
        sock.settimeout(0.25)
        while RUNNING:
            try:
                client, _ = sock.accept()
            except socket.timeout:
                continue
            with client:
                client.settimeout(0.25)
                try:
                    client.recv(1024)
                except (socket.timeout, OSError):
                    pass
                try:
                    client.sendall(b"SKAN-CORE-LAB\r\n")
                except OSError:
                    pass
    return 0


def udp_server(family: int, bind: str, port: int) -> int:
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((bind, port))
        sock.settimeout(0.25)
        while RUNNING:
            try:
                data, peer = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                if RUNNING:
                    raise
                break
            payload = data[:512] if data else b"SKAN-CORE-LAB-UDP"
            try:
                sock.sendto(payload, peer)
            except OSError:
                pass
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--family", choices=("ipv4", "ipv6"), required=True)
    parser.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be in 1..65535")

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    family = socket.AF_INET if args.family == "ipv4" else socket.AF_INET6
    if args.protocol == "tcp":
        return tcp_server(family, args.bind, args.port)
    return udp_server(family, args.bind, args.port)


if __name__ == "__main__":
    sys.exit(main())
