# PROVENANCE (mirror of .provenance/ledger.jsonl; ledger wins)
# written-by: codex/gpt-6 | 2026-11-13 | :/isolate-capstone-sources-v1
# modified-by: codex/gpt-6 | 2026-11-13 | fdeaacfb9f10fa420f943572f343014a8be6129d
# reviews: pending current exact-commit claude-code and grok-build approval
# END PROVENANCE
"""Synthetic fixtures only. Set GUARD_REQUIRE_ISOLATION=1 to forbid skips."""

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from guardlib import runner

REPO = str(Path(__file__).resolve().parents[1])


class Fixture:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="guard-test-", dir="/tmp")
        self.root = Path(self.temp.name)
        for name in ("cleared", "licensed", "unknown", "out", "cache", "tmp"):
            (self.root / name).mkdir(mode=0o700)
        (self.root / "cleared/public.txt").write_bytes(b"synthetic public clearance")
        (self.root / "cleared/notes.txt").write_bytes(b"synthetic personal interpretation")
        (self.root / "cleared/new.txt").write_bytes(b"synthetic unclassified addition")
        (self.root / "licensed/document.txt").write_bytes(b"SYNTHETIC_FORBIDDEN_SENTINEL")
        (self.root / "unknown/document.txt").write_bytes(b"SYNTHETIC_UNKNOWN_SENTINEL")
        self.policy = {
            "version": 1, "runtime": [{"source": "/usr", "target": "/usr"}],
            "input_roots": [{"id": "research", "path": str(self.root / "cleared"),
                             "files": [self.entry("public.txt", "PUBLIC/ALT"),
                                       self.entry("notes.txt", "NOTES")]}],
            "writable": {name: str(self.root / name) for name in ("out", "cache", "tmp")},
            "network": {"mode": "none"},
        }
        self.save()

    def entry(self, name, clearance="PUBLIC/ALT"):
        return {"path": name, "class": clearance,
                "sha256": hashlib.sha256((self.root / "cleared" / name).read_bytes()).hexdigest()}

    def save(self):
        self.path = self.root / "policy.json"
        self.path.write_text(json.dumps(self.policy))
        self.path.chmod(0o600)

    def cli(self, operation="check", code=None, **kwargs):
        command = [sys.executable, "-m", "guardlib.runner", operation,
                   "--policy", str(self.path)]
        if code is not None:
            command += ["--", "/usr/bin/python3", "-I", "-c", code]
        return subprocess.run(command, capture_output=True, cwd=REPO, timeout=40, **kwargs)

    def clean(self):
        self.temp.cleanup()


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()
        self.addCleanup(self.fixture.clean)

    def test_policy_accepts_only_explicit_clearance(self):
        f = self.fixture
        self.assertEqual(runner.load_policy(f.path), f.policy)
        for clearance in ("LICENSED", "PUBLIC", "ALT", "UNCLASSIFIED", "", None):
            with self.subTest(clearance=clearance):
                f.policy["input_roots"][0]["files"][0]["class"] = clearance
                f.save()
                with self.assertRaises(runner.IsolationError):
                    runner.load_policy(f.path)

    def test_invalid_policies_are_refused(self):
        f = self.fixture
        for name in ("../licensed/document.txt", "/etc/passwd", "a/../public.txt",
                     "a//b", ".", "a/./b", "a\x00b"):
            with self.subTest(name=name):
                f.policy["input_roots"][0]["files"][0]["path"] = name
                f.save()
                with self.assertRaises(runner.IsolationError):
                    runner.load_policy(f.path)

    def test_overlapping_roots_refused(self):
        f = self.fixture
        f.policy["writable"]["out"] = str(f.root / "cleared")
        f.save()
        with self.assertRaises(runner.IsolationError):
            runner.load_policy(f.path)

    def test_policy_under_exposed_root_refused(self):
        f = self.fixture
        f.policy["writable"]["tmp"] = str(f.root)
        f.save()
        with self.assertRaises(runner.IsolationError):
            runner.load_policy(f.path)

    def test_policy_duplicates_and_unknown_fields_refused(self):
        f = self.fixture
        f.path.write_text('{"version":1,"version":1}')
        with self.assertRaises(runner.IsolationError):
            runner.load_policy(f.path)
        f.policy["credential"] = "synthetic-secret"
        f.save()
        self.assertEqual(f.cli().returncode, 125)

    def test_unavailable_isolation_fails_without_command_execution(self):
        f = self.fixture
        with patch.object(runner, "BWRAP", "/nonexistent-bubblewrap"):
            with self.assertRaisesRegex(runner.IsolationError, "bubblewrap_missing"):
                with runner.Sandbox(runner.load_policy(f.path)):
                    self.fail("sandbox constructed without bubblewrap")
        with patch.object(runner.platform, "machine", return_value="unsupported"):
            with self.assertRaises(runner.IsolationError):
                runner.prerequisites()

    def test_errors_do_not_echo_policy_paths_content_or_secrets(self):
        f = self.fixture
        secret = "SYNTHETIC_SECRET_DO_NOT_LOG"
        f.policy["network"] = {"mode": secret}
        f.save()
        result = f.cli()
        self.assertEqual(result.returncode, 125)
        self.assertNotIn(secret.encode(), result.stderr + result.stdout)
        self.assertNotIn(str(f.root).encode(), result.stderr + result.stdout)
        result = subprocess.run([sys.executable, "-m", "guardlib.runner", secret],
                                capture_output=True, cwd=REPO)
        self.assertEqual(result.returncode, 125)
        self.assertNotIn(secret.encode(), result.stderr + result.stdout)


class IsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = Fixture()
        try:
            result = fixture.cli()
        finally:
            fixture.clean()
        if result.returncode:
            message = "real isolation unavailable: " + result.stderr.decode().strip()
            if os.environ.get("GUARD_REQUIRE_ISOLATION") == "1":
                raise AssertionError(message)
            raise unittest.SkipTest(message + "; GUARD_REQUIRE_ISOLATION=1 forbids skips")

    def setUp(self):
        self.fixture = Fixture()
        self.addCleanup(self.fixture.clean)

    def run_code(self, code, **kwargs):
        result = self.fixture.cli("run", code, **kwargs)
        stderr = (self.fixture.root / "out/agent.stderr")
        detail = stderr.read_text() if stderr.exists() else ""
        self.assertEqual(result.returncode, 0, result.stderr.decode() + detail)
        return result

    def test_actual_reads_writes_children_and_alternate_paths(self):
        f = self.fixture
        code = r'''
import os, pathlib, subprocess, sys
assert pathlib.Path('/inputs/research/public.txt').read_bytes() == b'synthetic public clearance'
assert pathlib.Path('/inputs/research/notes.txt').read_bytes() == b'synthetic personal interpretation'
def blocked(path, flags=os.O_RDONLY):
    try:
        fd = os.open(path, flags, 0o600)
    except OSError:
        return
    os.close(fd)
    raise AssertionError('filesystem operation succeeded')
paths = FORBIDDEN
paths += ['/inputs/research/new.txt', '/inputs/research/../../licensed/document.txt',
          '/proc/1/root' + FORBIDDEN[0], '/proc/self/root' + FORBIDDEN[0]]
for path in paths:
    blocked(path)
    # Actual independently exec'd child attempts the same filesystem read.
    result = subprocess.run([sys.executable, '-I', '-c',
        'import os,sys; os.open(sys.argv[1], os.O_RDONLY)', path], capture_output=True)
    assert result.returncode != 0
os.symlink(FORBIDDEN[0], '/out/alias')
blocked('/out/alias')
try:
    os.link(FORBIDDEN[0], '/out/hard-alias')
except OSError:
    pass
else:
    raise AssertionError('forbidden hardlink created')
for path in ['/outside', '/inputs/research/public.txt', '/usr/forbidden', '/guard/settings']:
    blocked(path, os.O_WRONLY | os.O_CREAT)
for root in ['/out', '/cache', '/tmp']:
    pathlib.Path(root + '/success').write_bytes(b'synthetic result')
print('SYNTHETIC_AGENT_OUTPUT_SEPARATE_FROM_AUDIT')
'''.replace("FORBIDDEN", repr([str(f.root / "licensed/document.txt"),
                               str(f.root / "unknown/document.txt"),
                               str(f.root / "cleared/public.txt"), str(f.path)]))
        result = self.run_code(code)
        for name in ("out", "cache", "tmp"):
            self.assertEqual((f.root / name / "success").read_bytes(), b"synthetic result")
        self.assertFalse((f.root / "outside").exists())
        for content in (b"SYNTHETIC_FORBIDDEN_SENTINEL", b"synthetic public clearance",
                        b"SYNTHETIC_AGENT_OUTPUT_SEPARATE_FROM_AUDIT"):
            self.assertNotIn(content, result.stderr + result.stdout)

    def test_fds_environment_and_host_sockets_are_not_inherited(self):
        f = self.fixture
        with open(f.root / "licensed/document.txt", "rb") as handle:
            os.set_inheritable(handle.fileno(), True)
            environment = dict(os.environ, SYNTHETIC_SECRET="DO_NOT_PASS", PYTHONPATH="/forbidden")
            self.run_code(r'''
import os, socket
assert 'SYNTHETIC_SECRET' not in os.environ
assert 'PYTHONPATH' not in os.environ
assert os.read(0, 100) == b''
for number in os.listdir('/proc/self/fd'):
    fd = int(number)
    if fd > 2:
        try:
            os.fstat(fd)
        except OSError:
            continue
        raise AssertionError('setup descriptor leaked')
for process in os.listdir('/proc'):
    if not process.isdigit():
        continue
    directory = '/proc/' + process + '/fd'
    try:
        handles = os.listdir(directory)
    except OSError:
        continue
    for handle in handles:
        # A directory FD in the namespace's init/reaper must not provide an
        # alternate handle to the old host root or a research directory.
        candidate = directory + '/' + handle
        for attempt in (candidate + HOST_FILE, candidate + '/document.txt'):
            try:
                leaked = os.open(attempt, os.O_RDONLY)
            except OSError:
                pass
            else:
                os.close(leaked)
                raise AssertionError('host directory descriptor leaked')
        try:
            assert os.readlink(candidate) != HOST_FILE
        except OSError:
            pass
for address in [('127.0.0.1', 1), ('1.1.1.1', 443)]:
    sock = socket.socket()
    sock.settimeout(0.2)
    assert sock.connect_ex(address) != 0
'''.replace("HOST_FILE", repr(str(f.root / "licensed/document.txt"))),
                          pass_fds=(handle.fileno(),), env=environment)

    def test_policy_edits_mount_and_user_namespace_cannot_widen_access(self):
        f = self.fixture
        self.run_code(r'''
import ctypes, os, pathlib, subprocess, sys
policy = HOST_POLICY
try:
    pathlib.Path(policy).write_text('{}')
except OSError:
    pass
else:
    raise AssertionError('host policy writable')
pathlib.Path('/out/fake-policy.json').write_text('{"allow":"/"}')
os.environ['GUARD_POLICY'] = '/out/fake-policy.json'
libc = ctypes.CDLL(None, use_errno=True)
assert libc.mount(b'/', b'/out', None, 4096, None) == -1
assert libc.unshare(0x10000000) == -1
assert libc.setns(-1, 0) == -1
pathlib.Path('/out/child.py').write_text('import os; os.open(' + repr(FORBIDDEN) + ',os.O_RDONLY)')
assert subprocess.call([sys.executable, '/out/child.py'], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL) != 0
'''.replace("HOST_POLICY", repr(str(f.path))).replace("FORBIDDEN", repr(str(f.root / "licensed/document.txt"))))
        self.assertEqual(json.loads(f.path.read_text()), f.policy)

    def test_existing_host_tcp_and_unix_services_are_unreachable(self):
        f = self.fixture
        with socket.socket() as tcp, socket.socket(socket.AF_UNIX) as unix:
            tcp.bind(("127.0.0.1", 0))
            tcp.listen()
            unix.bind(str(f.root / "host-service.sock"))
            unix.listen()
            # Establish these are live host services, not nonexistent targets.
            with socket.create_connection(tcp.getsockname()):
                pass
            self.run_code(r'''
import socket
for family, address in [(socket.AF_INET, ('127.0.0.1', PORT)),
                         (socket.AF_UNIX, UNIX_PATH)]:
    peer = socket.socket(family)
    peer.settimeout(0.2)
    assert peer.connect_ex(address) != 0
    peer.close()
'''.replace("PORT", str(tcp.getsockname()[1])).replace("UNIX_PATH", repr(str(f.root / "host-service.sock"))))

    def test_symlinks_hardlinks_special_files_and_changed_content_refused(self):
        f = self.fixture
        path = f.root / "cleared/public.txt"
        for kind in ("symlink", "hardlink", "fifo", "changed"):
            with self.subTest(kind=kind):
                path.unlink()
                if kind == "symlink":
                    path.symlink_to(f.root / "licensed/document.txt")
                elif kind == "hardlink":
                    os.link(f.root / "licensed/document.txt", path)
                elif kind == "fifo":
                    os.mkfifo(path)
                else:
                    path.write_bytes(b"new bytes not explicitly cleared")
                result = f.cli("run", "raise AssertionError('must not run')")
                self.assertEqual(result.returncode, 125)
                self.assertFalse((f.root / "out/agent.stdout").exists())
                self.assertNotIn(b"SYNTHETIC_FORBIDDEN_SENTINEL", result.stderr)

    def test_directory_symlink_and_reused_writable_root_refused(self):
        f = self.fixture
        (f.root / "alias").symlink_to(f.root / "cleared", target_is_directory=True)
        f.policy["input_roots"][0]["path"] = str(f.root / "alias")
        f.save()
        self.assertEqual(f.cli().returncode, 125)
        f.policy["input_roots"][0]["path"] = str(f.root / "cleared")
        (f.root / "out/old").write_text("synthetic stale output")
        f.save()
        self.assertEqual(f.cli().returncode, 125)

    def test_explicit_model_credential_never_enters_audit(self):
        f = self.fixture
        environment = dict(os.environ, OPENAI_API_KEY="synthetic-credential-do-not-log")
        result = subprocess.run([sys.executable, "-m", "guardlib.runner", "run",
            "--policy", str(f.path), "--credential", "OPENAI_API_KEY", "--",
            "/usr/bin/python3", "-I", "-c",
            "import os; assert os.environ['OPENAI_API_KEY'] == 'synthetic-credential-do-not-log'"],
            capture_output=True, env=environment, cwd=REPO, timeout=40)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertNotIn(b"synthetic-credential-do-not-log", result.stderr + result.stdout)

    def test_unusable_runtime_aborts_before_agent_launch(self):
        f = self.fixture
        (f.root / "runtime").mkdir()
        f.policy["runtime"] = [{"source": str(f.root / "runtime"), "target": "/usr"}]
        f.save()
        result = f.cli("run", "open('/out/must-not-exist', 'w').write('bad')")
        self.assertEqual(result.returncode, 125)
        self.assertIn(b"isolation_probe_failed", result.stderr)
        self.assertFalse((f.root / "out/must-not-exist").exists())
        self.assertFalse((f.root / "out/agent.stdout").exists())

    def test_allowlisted_nested_bind_mount_is_refused(self):
        # Create the adversarial mount in a disposable user/mount namespace,
        # never in the desktop's namespace. openat2 must return EXDEV.
        f = self.fixture
        (f.root / "cleared/nested").mkdir()
        code = '''
import os
from guardlib.runner import beneath, root_fd, IsolationError
fd = root_fd(ROOT)
try:
    leaked = beneath(fd, 'nested/document.txt', os.O_RDONLY)
except IsolationError:
    pass
else:
    os.close(leaked)
    raise AssertionError('bind mount crossed')
finally:
    os.close(fd)
'''.replace("ROOT", repr(str(f.root / "cleared")))
        # unshare provides capabilities only inside its new namespace.
        result = subprocess.run(["/usr/bin/unshare", "--user", "--map-root-user", "--mount",
                                 "/bin/sh", "-ec", 'mount --bind "$1" "$2"; exec "$3" -c "$4"',
                                 "guard-test", str(f.root / "licensed"), str(f.root / "cleared/nested"),
                                 sys.executable, code], capture_output=True, cwd=REPO, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_network_relay_mode_preserves_filesystem_boundary(self):
        f = self.fixture
        f.policy["network"] = {"mode": "https-relay", "hosts": ["api.example.com"]}
        f.save()
        self.run_code(r'''
import os, socket
assert os.environ['HTTPS_PROXY'] == 'http://127.0.0.1:18080'
peer = socket.create_connection(('127.0.0.1', 18080))
peer.sendall(b'CONNECT localhost:443 HTTP/1.1\r\n\r\n')
assert b'403 Forbidden' in peer.recv(4096)
peer.close()
try:
    os.open(FORBIDDEN, os.O_RDONLY)
except OSError:
    pass
else:
    raise AssertionError('online filesystem escape')
'''.replace("FORBIDDEN", repr(str(f.root / "licensed/document.txt"))))

    def test_approved_transport_works_from_restricted_process(self):
        from tests.test_relay import Echo
        import socketserver
        import threading
        f = self.fixture
        f.policy["network"] = {"mode": "https-relay", "hosts": ["synthetic.example"]}
        f.save()
        echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
        threading.Thread(target=echo.serve_forever, daemon=True).start()
        try:
            address = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", echo.server_address)]
            # The production resolver is separately tested to reject loopback.
            with patch.object(runner.relay, "public_addresses", return_value=address):
                with runner.Sandbox(runner.load_policy(f.path)) as sandbox:
                    code = sandbox.execute(["/usr/bin/python3", "-I", "-c", r'''
import socket
peer = socket.create_connection(('127.0.0.1', 18080))
peer.sendall(b'CONNECT synthetic.example:443 HTTP/1.1\r\n\r\n')
assert b'200 Connection Established' in peer.recv(4096)
peer.sendall(b'synthetic round trip')
assert peer.recv(4096) == b'synthetic round trip'
'''])
            self.assertEqual(code, 0, (f.root / "out/agent.stderr").read_text())
        finally:
            echo.shutdown()
            echo.server_close()


if __name__ == "__main__":
    unittest.main()
