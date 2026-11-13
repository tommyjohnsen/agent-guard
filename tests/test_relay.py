# PROVENANCE (mirror of .provenance/ledger.jsonl; ledger wins)
# written-by: codex/gpt-6 | 2026-11-13 | :/isolate-capstone-sources-v1
# modified-by: codex/gpt-6 | 2026-11-13 | fdeaacfb9f10fa420f943572f343014a8be6129d
# reviews: pending current exact-commit claude-code and grok-build approval
# END PROVENANCE
"""Relay tests use synthetic DNS and a local echo server, never credentials."""

import contextlib
import io
import socket
import socketserver
import tempfile
import threading
import unittest
from unittest.mock import patch

from guardlib import relay


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(self.request.recv(1024))


class RelayTests(unittest.TestCase):
    def test_private_local_mapped_multicast_and_mixed_dns_refused(self):
        for ip in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.1",
                   "::1", "fc00::1", "fe80::1", "::ffff:8.8.8.8", "224.0.0.1"):
            with self.subTest(ip=ip):
                family = socket.AF_INET6 if ":" in ip else socket.AF_INET
                addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
                             (family, socket.SOCK_STREAM, 6, "", (ip, 443))]
                with patch.object(socket, "getaddrinfo", return_value=addresses):
                    with self.assertRaises(ValueError):
                        relay.public_addresses("synthetic.example")

    def test_public_addresses_return_numeric_pinned_targets(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        with patch.object(socket, "getaddrinfo", return_value=addresses) as lookup:
            self.assertEqual(relay.public_addresses("synthetic.example"), addresses)
        lookup.assert_called_once_with("synthetic.example", 443, type=socket.SOCK_STREAM)

    def test_real_connect_tunnel_and_rejection_do_not_log_payload(self):
        with tempfile.TemporaryDirectory(prefix="guard-relay-") as directory:
            server = relay.start(directory + "/proxy", ["synthetic.example"])
            echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
            echo.daemon_threads = True
            threading.Thread(target=echo.serve_forever, daemon=True).start()
            try:
                output = io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    # Only the test replaces DNS validation to reach its echo
                    # fixture. Production never permits loopback addresses.
                    address = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", echo.server_address)]
                    with patch.object(relay, "public_addresses", return_value=address):
                        with socket.socket(socket.AF_UNIX) as peer:
                            peer.connect(directory + "/proxy")
                            peer.sendall(b"CONNECT synthetic.example:443 HTTP/1.1\r\n\r\n")
                            self.assertIn(b"200 Connection Established", peer.recv(4096))
                            peer.sendall(b"synthetic confidential payload")
                            self.assertEqual(peer.recv(4096), b"synthetic confidential payload")
                    for request in (b"CONNECT localhost:443 HTTP/1.1", b"CONNECT synthetic.example:80 HTTP/1.1",
                                    b"GET /secret HTTP/1.1", b"CONNECT 127.0.0.1:443 HTTP/1.1",
                                    b"CONNECT synthetic.example:443@localhost HTTP/1.1"):
                        with socket.socket(socket.AF_UNIX) as peer:
                            peer.connect(directory + "/proxy")
                            peer.sendall(request + b"\r\nSecret: synthetic-secret\r\n\r\n")
                            self.assertIn(b"403 Forbidden", peer.recv(4096))
                    with patch.object(socket, "getaddrinfo", return_value=[
                        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]):
                        with socket.socket(socket.AF_UNIX) as peer:
                            peer.connect(directory + "/proxy")
                            peer.sendall(b"CONNECT synthetic.example:443 HTTP/1.1\r\n\r\n")
                            self.assertIn(b"403 Forbidden", peer.recv(4096))
                self.assertEqual(output.getvalue(), "")
            finally:
                server.shutdown()
                server.server_close()
                echo.shutdown()
                echo.server_close()


if __name__ == "__main__":
    unittest.main()
