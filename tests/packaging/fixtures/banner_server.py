#!/usr/bin/env python3
import socket
import sys

port = int(sys.argv[1])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen()
    while True:
        connection, _ = server.accept()
        with connection:
            connection.settimeout(0.5)
            try:
                connection.recv(4096)
            except (TimeoutError, OSError):
                pass
            connection.sendall(b"HTTP/1.0 200 OK\r\nServer: SkanFixture/1.2\r\nContent-Length: 0\r\n\r\n")
