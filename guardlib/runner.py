# PROVENANCE (mirror of .provenance/ledger.jsonl; ledger wins)
# written-by: codex/gpt-6 | 2026-11-13 | :/isolate-capstone-sources-v1
# reviews: pending current exact-commit claude-code and grok-build approval
# END PROVENANCE
"""Fail-closed Linux source isolation, independent of the advisory gate."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import sys
import tempfile

from . import relay

BWRAP = "/usr/bin/bwrap"
PYTHON = "/usr/bin/python3"
CLASSES = {"PUBLIC/ALT", "NOTES"}
SAFE_ENV = {"PATH": "/usr/bin:/bin:/opt/runtime/bin", "HOME": "/tmp/home",
            "TMPDIR": "/tmp", "XDG_CACHE_HOME": "/cache",
            "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1",
            "SSL_CERT_FILE": "/inputs/certificates/ca-bundle.crt",
            "NODE_EXTRA_CA_CERTS": "/inputs/certificates/ca-bundle.crt"}
CREDENTIALS = {"OPENAI_API_KEY", "ANTHROPIC_API_KEY"}


class IsolationError(Exception):
    """Carries only a fixed diagnostic code, never caller-controlled text."""


def require(condition, code):
    if not condition:
        raise IsolationError(code)


def keys(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected), "policy_schema")


def absolute(value):
    require(isinstance(value, str) and value.startswith("/") and value != "/"
            and str(PurePosixPath(value)) == value
            and ".." not in PurePosixPath(value).parts and "\x00" not in value,
            "policy_path")
    return value


class OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64),
                ("resolve", ctypes.c_uint64)]


def beneath(root_fd, path, flags):
    """openat2: no symlinks, magic links, traversal or nested/bind mounts.

    Unlike realpath + open, resolution and opening are one kernel operation.
    Syscall 437 is shared by supported x86-64 and AArch64 Linux ABIs.
    """
    how = OpenHow(flags | os.O_CLOEXEC, 0, 0x08 | 0x04 | 0x02 | 0x01)
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(ctypes.c_long(437), ctypes.c_int(root_fd),
                          ctypes.c_char_p(os.fsencode(path)), ctypes.byref(how),
                          ctypes.c_size_t(ctypes.sizeof(how)))
    if result < 0:
        raise IsolationError("unsafe_or_unavailable_path_resolution")
    return result


def root_fd(path):
    absolute(path)
    # Resolve every component without symlinks. Explicit roots may themselves
    # be on separate filesystems; no mount may be crossed *below* those roots.
    fd = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in PurePosixPath(path).parts[1:]:
            next_fd = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW
                              | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def overlaps(first, second):
    a, b = PurePosixPath(first), PurePosixPath(second)
    return a == b or a in b.parents or b in a.parents


def no_nested_mounts(fd):
    path = os.readlink("/proc/self/fd/" + str(fd))
    require(not path.endswith(" (deleted)"), "root_changed")
    with open("/proc/self/mountinfo") as handle:
        for line in handle:
            mount = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)),
                           line.split()[4])
            require(not mount.startswith(path.rstrip("/") + "/"), "nested_mount")


def load_policy(path):
    policy_path = os.path.abspath(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == os.getuid() and not info.st_mode & 0o022,
                "unsafe_policy_file")
        raw = handle.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, "policy_size")
    # Reject duplicate keys instead of silently accepting the last policy.
    def unique(pairs):
        value = {}
        for key, entry in pairs:
            require(key not in value, "policy_duplicate_key")
            value[key] = entry
        return value
    policy = json.loads(raw, object_pairs_hook=unique)
    keys(policy, {"version", "runtime", "input_roots", "writable", "network"})
    require(type(policy["version"]) is int and policy["version"] == 1, "policy_version")
    require(isinstance(policy["runtime"], list) and policy["runtime"], "policy_runtime")
    targets = set()
    paths = []
    for item in policy["runtime"]:
        keys(item, {"source", "target"})
        absolute(item["source"])
        require(item["source"] not in {"/home", "/root", "/srv", "/mnt", "/media",
                                        "/run", "/proc", "/dev", "/sys", "/etc", "/var", "/tmp"}
                and PurePosixPath(item["source"]) not in
                (Path.home(), *Path.home().parents), "runtime_too_broad")
        require(item["target"] in {"/usr", "/opt/runtime"}
                and item["target"] not in targets, "policy_runtime_target")
        targets.add(item["target"])
        paths.append(item["source"])
    require("/usr" in targets, "policy_runtime_python")
    require(isinstance(policy["input_roots"], list), "policy_inputs")
    ids = set()
    for root in policy["input_roots"]:
        keys(root, {"id", "path", "files"})
        require(isinstance(root["id"], str)
                and re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", root["id"])
                and root["id"] not in ids, "policy_input_id")
        ids.add(root["id"])
        paths.append(absolute(root["path"]))
        require(isinstance(root["files"], list), "policy_files")
        names = set()
        for item in root["files"]:
            keys(item, {"path", "class", "sha256"})
            name = item["path"]
            require(isinstance(name, str) and name and not name.startswith("/")
                    and str(PurePosixPath(name)) == name
                    and ".." not in PurePosixPath(name).parts
                    and "\x00" not in name and name != "." and name not in names,
                    "policy_relative_path")
            names.add(name)
            require(isinstance(item["class"], str) and item["class"] in CLASSES,
                    "source_not_cleared")
            require(isinstance(item["sha256"], str)
                    and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]), "policy_digest")
    keys(policy["writable"], {"out", "cache", "tmp"})
    for path in policy["writable"].values():
        paths.append(absolute(path))
    # Roots cannot overlap each other or contain the policy.
    for index, first in enumerate(paths):
        require(not overlaps(first, policy_path), "policy_exposed")
        for second in paths[index + 1:]:
            require(not overlaps(first, second), "overlapping_roots")
    network = policy["network"]
    require(isinstance(network, dict), "policy_network")
    if network.get("mode") == "none":
        keys(network, {"mode"})
    else:
        keys(network, {"mode", "hosts"})
        require(network["mode"] == "https-relay"
                and isinstance(network["hosts"], list) and network["hosts"], "policy_network")
        for host in network["hosts"]:
            require(isinstance(host, str) and len(host) <= 253
                    and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+", host)
                    and not re.fullmatch(r"[0-9.]+", host)
                    and not host.endswith((".localhost", ".local")), "policy_endpoint")
    return policy


def prerequisites():
    require(sys.platform == "linux" and platform.machine() in {"x86_64", "aarch64"},
            "unsupported_platform")
    require(os.getuid() != 0, "root_not_supported")
    try:
        info = os.stat(BWRAP)
    except FileNotFoundError:
        raise IsolationError("bubblewrap_missing") from None
    require(info.st_uid == 0 and not info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID),
            "unsafe_bubblewrap")
    result = subprocess.run([BWRAP, "--version"], capture_output=True, close_fds=True,
                            env=SAFE_ENV, timeout=10, stdin=subprocess.DEVNULL)
    match = re.fullmatch(rb"bubblewrap (\d+)\.(\d+)\.(\d+)\s*", result.stdout)
    require(result.returncode == 0 and match
            and tuple(map(int, match.groups())) >= (0, 9, 0), "bubblewrap_version")
    # Actually exercise openat2, including its required resolution flags.
    fd = os.open("/", os.O_PATH | os.O_DIRECTORY)
    try:
        os.close(beneath(fd, ".", os.O_PATH | os.O_DIRECTORY))
    finally:
        os.close(fd)


class Sandbox:
    def __init__(self, policy, credentials=None):
        self.policy = policy
        self.credentials = credentials or {}
        require(set(self.credentials) <= CREDENTIALS
                and all(isinstance(value, str) and value for value in self.credentials.values()),
                "credential_selection")
        self.fds = []
        self.data_fds = []
        self.relay = None
        self.work = None

    def keep(self, fd):
        self.fds.append(fd)
        return fd

    def data(self, content):
        # Sealed memfds cannot be changed after validation or by the child.
        import fcntl
        fd = self.keep(os.memfd_create("guard-data", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING))
        self.data_fds.append(fd)
        view = memoryview(content)
        while view:
            view = view[os.write(fd, view):]
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                    | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return str(fd)

    def __enter__(self):
        try:
            return self.prepare()
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def prepare(self):
        prerequisites()
        self.work = tempfile.TemporaryDirectory(prefix="guard-run-", dir="/tmp")
        canary = Path(self.work.name) / "inaccessible"
        canary.write_bytes(b"synthetic forbidden probe")
        self.argv = [BWRAP, "--unshare-user", "--unshare-pid", "--unshare-ipc",
                     "--unshare-net", "--unshare-uts", "--disable-userns",
                     "--assert-userns-disabled", "--die-with-parent", "--new-session",
                     "--cap-drop", "ALL", "--clearenv"]
        for root in self.policy["runtime"]:
            fd = self.keep(root_fd(root["source"]))
            no_nested_mounts(fd)
            # Bind pinned roots, not mutable pathnames. Runtime is trusted
            # operator-curated software; it must contain no research or brokers.
            self.argv += ["--ro-bind-fd", str(fd), root["target"]]
        for name in ("bin", "sbin", "lib", "lib64"):
            self.argv += ["--symlink", "usr/" + name, "/" + name]
        self.argv += ["--proc", "/proc", "--dev", "/dev", "--dir", "/guard",
                      "--dir", "/inputs"]
        for root in self.policy["input_roots"]:
            fd = self.keep(root_fd(root["path"]))
            target = "/inputs/" + root["id"]
            self.argv += ["--dir", target]
            for item in root["files"]:
                source = beneath(fd, item["path"], os.O_RDONLY | os.O_NONBLOCK)
                with os.fdopen(source, "rb") as handle:
                    info = os.fstat(handle.fileno())
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                            "input_not_single_regular_file")
                    # Hash and expose the same immutable snapshot. No source
                    # directory or host-side source descriptor enters the child.
                    snapshot = self.keep(os.memfd_create("guard-input", os.MFD_CLOEXEC
                                                       | os.MFD_ALLOW_SEALING))
                    self.data_fds.append(snapshot)
                    digest = hashlib.sha256()
                    while chunk := handle.read(1024 * 1024):
                        digest.update(chunk)
                        view = memoryview(chunk)
                        while view:
                            view = view[os.write(snapshot, view):]
                    require(digest.hexdigest() == item["sha256"], "input_digest_changed")
                    import fcntl
                    fcntl.fcntl(snapshot, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE
                                | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
                    os.lseek(snapshot, 0, os.SEEK_SET)
                    self.argv += ["--ro-bind-data", str(snapshot), target + "/" + item["path"]]
        self.outputs = {}
        for name, path in self.policy["writable"].items():
            fd = self.keep(root_fd(path))
            no_nested_mounts(fd)
            info = os.fstat(fd)
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                    "writable_owner_or_mode")
            listing = self.keep(os.open(".", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd))
            require(not os.listdir(listing), "writable_not_empty")
            self.outputs[name] = fd
            self.argv += ["--bind-fd", str(fd), "/" + name]
        settings = {"canary": str(canary),
                    "namespaces": {name: os.readlink("/proc/self/ns/" + name)
                                   for name in ("user", "mnt", "pid", "net", "ipc", "uts")},
                    "relay": self.policy["network"]["mode"] == "https-relay"}
        if settings["relay"]:
            socket_path = str(Path(self.work.name) / "relay.sock")
            self.relay = relay.start(socket_path, self.policy["network"]["hosts"])
            self.argv += ["--ro-bind", socket_path, "/guard/relay.sock"]
        for name, value in SAFE_ENV.items():
            self.argv += ["--setenv", name, value]
        if settings["relay"]:
            for name in ("HTTPS_PROXY", "https_proxy"):
                self.argv += ["--setenv", name, "http://127.0.0.1:18080"]
        bootstrap = Path(__file__).with_name("_sandbox.py").read_bytes()
        self.argv += ["--ro-bind-data", self.data(bootstrap), "/guard/bootstrap.py",
                      "--ro-bind-data", self.data(json.dumps(self.credentials).encode()), "/guard/credentials",
                      "--ro-bind-data", self.data(json.dumps(settings).encode()), "/guard/settings",
                      "--ro-bind-data", self.data(b"synthetic cleared probe"), "/guard/allowed",
                      "--remount-ro", "/", "--chdir", "/out", "--", PYTHON,
                      "-I", "/guard/bootstrap.py"]
        return self

    def execute(self, command, check=False):
        # Never inherit caller FDs, stdin, environment, terminal, cwd or sockets.
        # Agent output is an output artifact, separate from the metadata audit.
        if not check:
            self.execute([], check=True)
        # Bubblewrap consumes --ro-bind-data's shared file offsets. Rewind
        # before each launch so the command receives the same sealed bytes
        # as preflight, including the bootstrap itself.
        for fd in self.data_fds:
            os.lseek(fd, 0, os.SEEK_SET)
        if check:
            result = subprocess.run(self.argv + ["check"], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    env=SAFE_ENV, cwd="/", close_fds=True,
                                    pass_fds=tuple(self.fds), timeout=30)
            require(result.returncode == 0, "isolation_probe_failed")
            return 0
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        with os.fdopen(os.open("agent.stdout", flags, 0o600, dir_fd=self.outputs["out"]), "wb") as out:
            with os.fdopen(os.open("agent.stderr", flags, 0o600, dir_fd=self.outputs["out"]), "wb") as err:
                return subprocess.call(self.argv + ["run"] + command,
                                       stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       env=SAFE_ENV, cwd="/", close_fds=True,
                                       pass_fds=tuple(self.fds))

    def __exit__(self, *_):
        if self.relay is not None:
            self.relay.shutdown()
            self.relay.server_close()
        for fd in self.fds:
            os.close(fd)
        if self.work is not None:
            self.work.cleanup()


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise IsolationError("command_syntax")


def main(argv=None):
    try:
        parser = Parser(description=__doc__)
        parser.add_argument("operation", choices=("check", "run"))
        parser.add_argument("--policy", required=True)
        parser.add_argument("--credential", action="append", default=[],
                            help="explicitly pass OPENAI_API_KEY or ANTHROPIC_API_KEY from environment")
        args, command = parser.parse_known_args(argv)
        if command[:1] == ["--"]:
            command = command[1:]
        require((args.operation == "check" and not command)
                or (args.operation == "run" and command and command[0].startswith("/")),
                "command_syntax")
        policy = load_policy(args.policy)
        require(set(args.credential) <= CREDENTIALS, "credential_selection")
        credentials = {name: os.environ.get(name, "") for name in args.credential}
        with Sandbox(policy, credentials) as sandbox:
            code = sandbox.execute(command, check=args.operation == "check")
        print(json.dumps({"event": args.operation, "status": "enforceable" if args.operation == "check"
                          else "exited", "code": code}), file=sys.stderr)
        return code if 0 <= code <= 255 else 128 + abs(code)
    except IsolationError as error:
        print(json.dumps({"event": "refused", "reason": str(error)}), file=sys.stderr)
    except (OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError):
        print(json.dumps({"event": "refused", "reason": "prerequisite_or_policy_failure"}), file=sys.stderr)
    return 125


if __name__ == "__main__":
    sys.exit(main())
