# PROVENANCE (mirror of .provenance/ledger.jsonl; ledger wins)
# written-by: codex/gpt-6 | 2026-11-13 | :/isolate-capstone-sources-v1
# modified-by: codex/gpt-6 | 2026-11-13 | fdeaacfb9f10fa420f943572f343014a8be6129d
# reviews: pending current exact-commit claude-code and grok-build approval
# END PROVENANCE
"""Standalone in-namespace bootstrap, copied read-only by guard-run.

Imports only the isolated runtime's stdlib; never imports the host checkout.
"""

import json
import os
import socket
import socketserver
import subprocess
import sys
import threading


def probe(settings):
    for name, host_namespace in settings["namespaces"].items():
        assert os.readlink("/proc/self/ns/" + name) != host_namespace
    assert open("/guard/allowed", "rb").read() == b"synthetic cleared probe"
    for path in (settings["canary"], "/proc/1/root" + settings["canary"],
                 "/inputs/../" + settings["canary"].lstrip("/")):
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError:
            pass
        else:
            os.close(fd)
            raise RuntimeError("probe_read")
    for root in ("/out", "/cache", "/tmp"):
        path = root + "/.guard-probe"
        with open(path, "xb") as handle:
            handle.write(b"synthetic output")
        os.unlink(path)
    for path in ("/escape", "/usr/.guard-write", "/inputs/.guard-write",
                 "/guard/allowed"):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        except OSError:
            pass
        else:
            os.close(fd)
            raise RuntimeError("probe_write")
    status = open("/proc/self/status").read()
    assert "NoNewPrivs:\t1" in status
    assert "CapEff:\t0000000000000000" in status


class Forward(socketserver.BaseRequestHandler):
    def handle(self):
        # This untrusted in-sandbox forwarder has no host networking. The
        # trusted host relay validates CONNECT even if this code is replaced.
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            peer.connect("/guard/relay.sock")
            import select
            while True:
                ready, _, _ = select.select([peer, self.request], [], [], 60)
                if not ready:
                    break
                for endpoint in ready:
                    chunk = endpoint.recv(65536)
                    if not chunk:
                        return
                    (peer if endpoint is self.request else self.request).sendall(chunk)
        except OSError:
            pass
        finally:
            peer.close()


if __name__ == "__main__":
    try:
        settings = json.load(open("/guard/settings"))
        probe(settings)
        if sys.argv[1] == "check":
            sys.exit(0)
        os.makedirs('/tmp/home', mode=0o700, exist_ok=True)
        os.environ.update(json.load(open('/guard/credentials')))
        if settings["relay"]:
            server = socketserver.ThreadingTCPServer(("127.0.0.1", 18080), Forward)
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
        # No inherited setup FDs; stdin and output files were replaced by the
        # trusted launcher. Command arguments and output never enter audit.
        sys.exit(subprocess.call(sys.argv[2:], close_fds=True))
    except Exception:
        # No exception text or traceback: a hostile argv/path can hold secrets.
        sys.exit(125)
