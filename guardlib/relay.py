# PROVENANCE (mirror of .provenance/ledger.jsonl; ledger wins)
# written-by: codex/gpt-6 | 2026-11-13 | :/isolate-capstone-sources-v1
# reviews: pending current exact-commit claude-code and grok-build approval
# END PROVENANCE
"""Narrow host-side CONNECT relay. No file, tool, credential or model APIs.

Only a named public endpoint on TCP 443 is reachable. TLS remains end to end.
This transport is deliberately outside the filesystem sandbox.
"""

from __future__ import annotations

import ipaddress
import re
import select
import socket
import socketserver
import threading


def public_addresses(host: str) -> list[tuple]:
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not addresses:
        raise ValueError("relay_resolution")
    for _, _, _, _, address in addresses:
        ip = ipaddress.ip_address(address[0])
        if (not ip.is_global or ip.is_multicast or ip.is_reserved
                or (ip.version == 6 and ip.ipv4_mapped is not None)):
            raise ValueError("relay_address")
    return addresses


def pump(left: socket.socket, right: socket.socket) -> None:
    """Bounded buffers, no payload logging; terminate on idle or disconnect."""
    for endpoint in (left, right):
        endpoint.settimeout(30)
    while True:
        ready, _, _ = select.select([left, right], [], [], 60)
        if not ready:
            return
        for endpoint in ready:
            chunk = endpoint.recv(65536)
            if not chunk:
                return
            (right if endpoint is left else left).sendall(chunk)


class Relay(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, path: str, hosts: list[str]):
        self.hosts = frozenset(hosts)
        super().__init__(path, RelayHandler)


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        upstream = None
        try:
            self.request.settimeout(10)
            header = bytearray()
            # Do not consume TLS bytes following CONNECT.
            while not header.endswith(b"\r\n\r\n"):
                chunk = self.request.recv(1)
                if not chunk or len(header) >= 8192:
                    raise ValueError("relay_header")
                header.extend(chunk)
            line = bytes(header).split(b"\r\n", 1)[0].decode("ascii")
            match = re.fullmatch(r"CONNECT ([a-z0-9.-]+):443 HTTP/1\.[01]", line)
            if not match or match[1] not in self.server.hosts:
                raise ValueError("relay_endpoint")
            # Validate every result before connecting to a numeric address;
            # never perform a second hostname lookup (DNS rebinding).
            addresses = public_addresses(match[1])
            for family, kind, protocol, _, address in addresses:
                candidate = socket.socket(family, kind, protocol)
                candidate.settimeout(10)
                try:
                    candidate.connect(address)
                    upstream = candidate
                    break
                except OSError:
                    candidate.close()
            if upstream is None:
                raise ValueError("relay_connect")
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            pump(self.request, upstream)
        except (OSError, ValueError, UnicodeError):
            # Never echo peer data or exception text (may contain secrets).
            try:
                self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
        finally:
            if upstream is not None:
                upstream.close()


def start(path: str, hosts: list[str]) -> Relay:
    server = Relay(path, hosts)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
