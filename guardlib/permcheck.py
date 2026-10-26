# PROVENANCE (mirror of .provenance/ledger.jsonl; ledger wins)
# written-by: unknown (pre-provenance) | 2026-10-09 | f032f17
# modified-by: codex/gpt-5.6-sol | 2026-10-26 | 1aaa682 | check forbidden default ACL principals and add provenance block
# reviewed-by: claude-code/claude-opus-5-5 | 2026-10-26 | APPROVE
# reviewed-by: grok-build/grok-4.7 | 2026-10-26 | APPROVE
# END PROVENANCE
"""Filesystem permission and ACL verifier.

Checks mode bits, owner and group, POSIX ACL named entries, the mask, default
ACLs, and world-readable / world-writable exposure against an expected policy.

The design separates three concerns so each is testable on its own:

  * ``parse_getfacl`` is pure text -> :class:`Acl`. Every ACL rule can be
    exercised from fixture text, including hosts where ``setfacl`` cannot
    create the entry under test.
  * ``collect`` gathers facts about a real path and shells out to read-only
    ``getfacl`` when available, degrading to mode bits when it is not.
  * ``verify`` compares facts to a :class:`PathPolicy` and never touches disk.

The rule that motivates the split is POSIX mask clipping: a named ACL entry
granting ``r-x`` under ``mask::---`` grants nothing. A verifier that reads the
declared permission and ignores the mask reports access that does not exist,
so :func:`effective_perms` is applied to every named entry and to the owning
group class, and deliberately *not* to ``user::`` or ``other::``, which the
mask does not constrain.
"""

from __future__ import annotations

import grp
import os
import pwd
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence

READ, WRITE, EXEC = 4, 2, 1

_PERM_RE = re.compile(r"\A[r-][w-][xXt-]\Z")
_GETFACL_TIMEOUT = 10

# The qualifier libacl most often prints for an unmapped id. It is the only
# one worth naming, but it is not the only one that occurs: any uid or gid
# without a passwd or group entry prints numerically, so recognising this
# single value misses every other unmapped principal. Every numeric qualifier
# is resolved through pwd/grp instead, and this constant is kept only because
# it is the value an operator will see most and search for.
UNRESOLVED_QUALIFIER = "4294967295"

_NUMERIC_RE = re.compile(r"\A[0-9]+\Z")


def _lookup_user_id(value: int) -> str | None:
    try:
        return pwd.getpwuid(value).pw_name
    except (KeyError, OverflowError, ValueError):
        return None


def _lookup_user_name(value: str) -> int | None:
    try:
        return pwd.getpwnam(value).pw_uid
    except KeyError:
        return None


def _lookup_group_id(value: int) -> str | None:
    try:
        return grp.getgrgid(value).gr_name
    except (KeyError, OverflowError, ValueError):
        return None


def _lookup_group_name(value: str) -> int | None:
    try:
        return grp.getgrnam(value).gr_gid
    except KeyError:
        return None


@dataclass(frozen=True)
class PrincipalResolver:
    """How numeric and named ACL qualifiers are mapped to the local namespace.

    Injectable so the resolution rules can be tested against a known namespace
    rather than against whatever accounts happen to exist on the host.
    """

    user_by_id: "Callable[[int], str | None]" = _lookup_user_id
    user_by_name: "Callable[[str], int | None]" = _lookup_user_name
    group_by_id: "Callable[[int], str | None]" = _lookup_group_id
    group_by_name: "Callable[[str], int | None]" = _lookup_group_name

    def resolve(self, kind: str, qualifier: str) -> "QualifierResolution":
        numeric = bool(_NUMERIC_RE.match(qualifier))
        if kind == "user":
            by_id, by_name = self.user_by_id, self.user_by_name
        elif kind == "group":
            by_id, by_name = self.group_by_id, self.group_by_name
        else:  # pragma: no cover - only user and group carry qualifiers
            return QualifierResolution(kind, qualifier, numeric, None, None, False)
        if numeric:
            identifier = int(qualifier)
            name = by_id(identifier)
            return QualifierResolution(
                kind, qualifier, True, identifier, name, name is not None
            )
        identifier = by_name(qualifier)
        return QualifierResolution(
            kind, qualifier, False, identifier, qualifier, identifier is not None
        )


@dataclass(frozen=True)
class QualifierResolution:
    """The outcome of mapping one ACL qualifier through pwd or grp."""

    kind: str
    qualifier: str
    numeric: bool
    identifier: int | None
    name: str | None
    resolved: bool

    def label(self) -> str:
        if self.resolved and self.numeric:
            return f"{self.qualifier} ({self.name})"
        if self.resolved:
            return f"{self.qualifier} (uid/gid {self.identifier})"
        shape = "numeric id with no entry" if self.numeric else "name with no entry"
        return f"{self.qualifier} (unresolved: {shape})"


DEFAULT_RESOLVER = PrincipalResolver()


def perms_to_bits(perms: str) -> int:
    """Convert an ``rwx``-style triad to bits. Unknown characters are ignored."""
    bits = 0
    if len(perms) >= 1 and perms[0] == "r":
        bits |= READ
    if len(perms) >= 2 and perms[1] == "w":
        bits |= WRITE
    if len(perms) >= 3 and perms[2] in ("x", "X", "t", "s"):
        bits |= EXEC
    return bits


def bits_to_perms(bits: int) -> str:
    return (
        ("r" if bits & READ else "-")
        + ("w" if bits & WRITE else "-")
        + ("x" if bits & EXEC else "-")
    )


@dataclass(frozen=True)
class AclEntry:
    """One ACL entry.

    ``kind`` is ``user``, ``group``, ``mask`` or ``other``. ``qualifier`` is the
    user or group name for named entries and ``None`` for the base entries
    ``user::``, ``group::``, ``mask::`` and ``other::``.
    """

    kind: str
    qualifier: str | None
    perms: str
    is_default: bool = False

    @property
    def is_named(self) -> bool:
        return self.qualifier is not None

    @property
    def bits(self) -> int:
        return perms_to_bits(self.perms)

    @property
    def is_numeric_qualifier(self) -> bool:
        return self.qualifier is not None and bool(_NUMERIC_RE.match(self.qualifier))

    def resolution(
        self, resolver: PrincipalResolver | None = None
    ) -> QualifierResolution | None:
        """Map this entry's qualifier, or None when it has none."""
        if self.qualifier is None:
            return None
        return (resolver or DEFAULT_RESOLVER).resolve(self.kind, self.qualifier)

    @property
    def is_unresolved(self) -> bool:
        """True when a numeric qualifier has no passwd or group entry here.

        Deliberately limited to numeric qualifiers: a *name* that does not
        resolve is a different condition, reported separately, and keeping
        them apart stops a policy written on one host from reading as an
        unmapped-id incident on another.
        """
        if not self.is_numeric_qualifier:
            return False
        resolution = self.resolution()
        return resolution is not None and not resolution.resolved

    @property
    def is_unknown_principal(self) -> bool:
        """True when a *named* qualifier has no entry in this namespace."""
        if self.qualifier is None or self.is_numeric_qualifier:
            return False
        resolution = self.resolution()
        return resolution is not None and not resolution.resolved

    def label(self) -> str:
        prefix = "default:" if self.is_default else ""
        qualifier = self.qualifier if self.qualifier is not None else ""
        return f"{prefix}{self.kind}:{qualifier}:{self.perms}"


def mask_applies_to(entry: AclEntry) -> bool:
    """POSIX 1003.1e: the mask constrains named entries and the owning group.

    It does not constrain ``user::`` (the owner) or ``other::``.
    """
    if entry.kind == "mask" or entry.kind == "other":
        return False
    if entry.kind == "user" and not entry.is_named:
        return False
    return True


def effective_perms(entry: AclEntry, mask: AclEntry | None) -> str:
    """Permissions actually granted, after mask clipping."""
    if mask is None or not mask_applies_to(entry):
        return bits_to_perms(entry.bits)
    return bits_to_perms(entry.bits & mask.bits)


@dataclass
class Acl:
    entries: list[AclEntry] = field(default_factory=list)
    default_entries: list[AclEntry] = field(default_factory=list)
    available: bool = True

    @property
    def mask(self) -> AclEntry | None:
        for entry in self.entries:
            if entry.kind == "mask":
                return entry
        return None

    @property
    def default_mask(self) -> AclEntry | None:
        for entry in self.default_entries:
            if entry.kind == "mask":
                return entry
        return None

    def named(self, kind: str | None = None) -> list[AclEntry]:
        return [
            entry
            for entry in self.entries
            if entry.is_named and (kind is None or entry.kind == kind)
        ]

    def named_default(self, kind: str | None = None) -> list[AclEntry]:
        """Named entries of the *default* ACL, which `named` does not return."""
        return [
            entry
            for entry in self.default_entries
            if entry.is_named and (kind is None or entry.kind == kind)
        ]

    def all_named(self, kind: str | None = None) -> list[AclEntry]:
        """Named entries of both the access and the default ACL.

        A check that reads only the access ACL misses a default entry
        entirely, and a default entry is what every file created in the
        directory afterwards inherits - so an unmapped principal there is the
        more durable defect, not the lesser one.
        """
        return self.named(kind) + self.named_default(kind)

    def find_named(self, kind: str, qualifier: str) -> AclEntry | None:
        for entry in self.entries:
            if entry.kind == kind and entry.qualifier == qualifier:
                return entry
        return None

    def find_named_default(self, kind: str, qualifier: str) -> AclEntry | None:
        """Find a named entry in the default ACL, if present."""
        for entry in self.default_entries:
            if entry.kind == kind and entry.qualifier == qualifier:
                return entry
        return None

    def effective_for(self, kind: str, qualifier: str) -> str | None:
        """Effective permissions for a named entry, or None if absent."""
        entry = self.find_named(kind, qualifier)
        if entry is None:
            return None
        return effective_perms(entry, self.mask)

    @property
    def has_default(self) -> bool:
        return bool(self.default_entries)


def parse_getfacl(text: str) -> Acl:
    """Parse ``getfacl`` output. Comment lines and ``#effective`` are ignored.

    The effective permission is recomputed from the mask rather than trusted
    from the comment, so the result is correct even when the comment is absent.
    """
    acl = Acl()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Drop any trailing "#effective:rwx" annotation.
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        is_default = line.startswith("default:")
        if is_default:
            line = line[len("default:") :]
        parts = line.split(":")
        if len(parts) != 3:
            continue
        kind, qualifier, perms = parts[0], parts[1], parts[2]
        if kind not in ("user", "group", "mask", "other"):
            continue
        if not _PERM_RE.match(perms):
            continue
        entry = AclEntry(
            kind=kind,
            qualifier=qualifier or None,
            perms=perms,
            is_default=is_default,
        )
        if is_default:
            acl.default_entries.append(entry)
        else:
            acl.entries.append(entry)
    return acl


def read_acl(path: str, timeout: int = _GETFACL_TIMEOUT) -> Acl:
    """Read the ACL with read-only ``getfacl``. Never raises on absence."""
    binary = shutil.which("getfacl")
    if binary is None:
        return Acl(available=False)
    try:
        completed = subprocess.run(
            [binary, "-p", "--absolute-names", path],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return Acl(available=False)
    if completed.returncode != 0:
        return Acl(available=False)
    return parse_getfacl(completed.stdout)


@dataclass
class PathFacts:
    path: str
    exists: bool
    is_dir: bool = False
    is_symlink: bool = False
    mode: int = 0
    owner: str | None = None
    group: str | None = None
    uid: int = -1
    gid: int = -1
    nlink: int = 0
    acl: Acl = field(default_factory=lambda: Acl(available=False))

    @property
    def mode_octal(self) -> str:
        return format(self.mode, "04o")

    @property
    def world_readable(self) -> bool:
        return bool(self.mode & stat.S_IROTH)

    @property
    def world_writable(self) -> bool:
        return bool(self.mode & stat.S_IWOTH)

    @property
    def group_readable(self) -> bool:
        return bool(self.mode & stat.S_IRGRP)

    @property
    def group_writable(self) -> bool:
        return bool(self.mode & stat.S_IWGRP)

    @property
    def setuid(self) -> bool:
        return bool(self.mode & stat.S_ISUID)

    @property
    def setgid(self) -> bool:
        return bool(self.mode & stat.S_ISGID)

    @property
    def sticky(self) -> bool:
        return bool(self.mode & stat.S_ISVTX)


def _name_for_uid(uid: int) -> str | None:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def _name_for_gid(gid: int) -> str | None:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return None


def collect(path: str | os.PathLike[str], with_acl: bool = True) -> PathFacts:
    """Gather facts about a path. A missing path yields ``exists=False``."""
    name = os.fspath(path)
    try:
        info = os.lstat(name)
    except OSError:
        return PathFacts(path=name, exists=False)
    is_symlink = stat.S_ISLNK(info.st_mode)
    facts = PathFacts(
        path=name,
        exists=True,
        is_dir=stat.S_ISDIR(info.st_mode),
        is_symlink=is_symlink,
        mode=stat.S_IMODE(info.st_mode),
        owner=_name_for_uid(info.st_uid),
        group=_name_for_gid(info.st_gid),
        uid=info.st_uid,
        gid=info.st_gid,
        nlink=info.st_nlink,
    )
    if with_acl and not is_symlink:
        facts.acl = read_acl(name)
    return facts


@dataclass(frozen=True)
class PermFinding:
    path: str
    check: str
    message: str
    expected: str | None = None
    actual: str | None = None
    severity: str = "high"

    def format(self) -> str:
        detail = ""
        if self.expected is not None or self.actual is not None:
            detail = f" (expected {self.expected}, actual {self.actual})"
        return f"{self.path}: [{self.severity}] {self.check}: {self.message}{detail}"


@dataclass
class PathPolicy:
    """Expected state for a path.

    Every field is optional; ``None`` means "do not check". ``mode_exactly``
    and ``mode_at_most`` are both supported because some paths must match a
    mode precisely while others only need to be no more permissive than a
    ceiling.
    """

    name: str = "policy"
    mode_exactly: int | None = None
    mode_at_most: int | None = None
    owner: str | None = None
    group: str | None = None
    allow_world_readable: bool = False
    allow_world_writable: bool = False
    allow_group_writable: bool = True
    allow_setuid: bool = False
    allow_setgid: bool = True
    # Named ACL entries that must be present *and effective* after mask clipping,
    # as (kind, qualifier, minimum perms), e.g. ("user", "agent", "r--").
    require_effective: Sequence[tuple[str, str, str]] = ()
    # Named ACL entries that must not be present at all.
    forbid_named: Sequence[tuple[str, str]] = ()
    mask_exactly: str | None = None
    require_default_acl: bool | None = None
    forbid_unresolved_named: bool = False
    # How qualifiers are mapped. None means the live pwd/grp namespace.
    resolver: PrincipalResolver | None = None
    must_exist: bool = True
    forbid_symlink: bool = False


def _mode_findings(facts: PathFacts, policy: PathPolicy) -> list[PermFinding]:
    findings: list[PermFinding] = []
    if policy.mode_exactly is not None and facts.mode != policy.mode_exactly:
        findings.append(
            PermFinding(
                facts.path,
                "mode_exactly",
                "mode does not match policy",
                format(policy.mode_exactly, "04o"),
                facts.mode_octal,
            )
        )
    if policy.mode_at_most is not None:
        extra = facts.mode & ~policy.mode_at_most
        if extra:
            findings.append(
                PermFinding(
                    facts.path,
                    "mode_at_most",
                    f"mode grants more than the ceiling (extra bits {format(extra, '04o')})",
                    f"<= {format(policy.mode_at_most, '04o')}",
                    facts.mode_octal,
                )
            )
    if facts.world_readable and not policy.allow_world_readable:
        findings.append(
            PermFinding(
                facts.path,
                "world_readable",
                "path is world-readable",
                "no o+r",
                facts.mode_octal,
                severity="high",
            )
        )
    if facts.world_writable and not policy.allow_world_writable:
        findings.append(
            PermFinding(
                facts.path,
                "world_writable",
                "path is world-writable",
                "no o+w",
                facts.mode_octal,
                severity="critical",
            )
        )
    if facts.group_writable and not policy.allow_group_writable:
        findings.append(
            PermFinding(
                facts.path,
                "group_writable",
                "path is group-writable",
                "no g+w",
                facts.mode_octal,
            )
        )
    if facts.setuid and not policy.allow_setuid:
        findings.append(
            PermFinding(
                facts.path, "setuid", "setuid bit is set", "no setuid", facts.mode_octal,
                severity="critical",
            )
        )
    if facts.setgid and not policy.allow_setgid:
        findings.append(
            PermFinding(
                facts.path, "setgid", "setgid bit is set", "no setgid", facts.mode_octal
            )
        )
    return findings


def _ownership_findings(facts: PathFacts, policy: PathPolicy) -> list[PermFinding]:
    findings: list[PermFinding] = []
    if policy.owner is not None and facts.owner != policy.owner:
        findings.append(
            PermFinding(
                facts.path,
                "owner",
                "owner does not match policy",
                policy.owner,
                facts.owner if facts.owner is not None else str(facts.uid),
            )
        )
    if policy.group is not None and facts.group != policy.group:
        findings.append(
            PermFinding(
                facts.path,
                "group",
                "group does not match policy",
                policy.group,
                facts.group if facts.group is not None else str(facts.gid),
            )
        )
    return findings


def _acl_findings(facts: PathFacts, policy: PathPolicy) -> list[PermFinding]:
    findings: list[PermFinding] = []
    needs_acl = bool(
        policy.require_effective
        or policy.forbid_named
        or policy.mask_exactly is not None
        or policy.require_default_acl is not None
        or policy.forbid_unresolved_named
    )
    if needs_acl and not facts.acl.available:
        findings.append(
            PermFinding(
                facts.path,
                "acl_unavailable",
                "policy requires ACL checks but the ACL could not be read",
                "readable ACL",
                "unavailable",
                severity="medium",
            )
        )
        return findings

    for kind, qualifier, minimum in policy.require_effective:
        entry = facts.acl.find_named(kind, qualifier)
        if entry is None:
            findings.append(
                PermFinding(
                    facts.path,
                    "require_effective",
                    f"required ACL entry {kind}:{qualifier} is absent",
                    f"{kind}:{qualifier}:{minimum}",
                    "absent",
                )
            )
            continue
        granted = effective_perms(entry, facts.acl.mask)
        want = perms_to_bits(minimum)
        if perms_to_bits(granted) & want != want:
            mask = facts.acl.mask
            reason = "declared but clipped by mask" if mask and (
                entry.bits & ~mask.bits
            ) else "insufficient permissions"
            findings.append(
                PermFinding(
                    facts.path,
                    "require_effective",
                    f"ACL entry {kind}:{qualifier} is not effective: {reason}",
                    f"{kind}:{qualifier}:{minimum}",
                    f"declared {entry.perms}, effective {granted}"
                    + (f", mask {mask.perms}" if mask else ""),
                )
            )

    for kind, qualifier in policy.forbid_named:
        candidates = (
            (facts.acl.find_named(kind, qualifier), facts.acl.mask, "access ACL"),
            (
                facts.acl.find_named_default(kind, qualifier),
                facts.acl.default_mask,
                "default ACL",
            ),
        )
        for entry, mask, where in candidates:
            if entry is None:
                continue
            granted = effective_perms(entry, mask)
            findings.append(
                PermFinding(
                    facts.path,
                    "forbid_named",
                    f"forbidden ACL entry {kind}:{qualifier} is present in {where}",
                    "absent",
                    f"declared {entry.perms}, effective {granted}",
                )
            )

    if policy.mask_exactly is not None:
        mask = facts.acl.mask
        actual = mask.perms if mask else "absent"
        if actual != policy.mask_exactly:
            findings.append(
                PermFinding(
                    facts.path, "mask_exactly", "ACL mask does not match policy",
                    policy.mask_exactly, actual,
                )
            )

    if policy.require_default_acl is not None:
        if policy.require_default_acl and not facts.acl.has_default:
            findings.append(
                PermFinding(
                    facts.path, "default_acl", "default ACL is required but absent",
                    "present", "absent",
                )
            )
        if not policy.require_default_acl and facts.acl.has_default:
            findings.append(
                PermFinding(
                    facts.path, "default_acl", "default ACL is present but forbidden",
                    "absent", "present",
                )
            )

    if policy.forbid_unresolved_named:
        resolver = policy.resolver or DEFAULT_RESOLVER
        for entry in facts.acl.all_named():
            resolution = entry.resolution(resolver)
            if resolution is None or resolution.resolved:
                continue
            where = "default ACL" if entry.is_default else "access ACL"
            check = (
                "unresolved_named" if entry.is_numeric_qualifier
                else "unknown_named_principal"
            )
            problem = (
                "names a numeric id with no passwd or group entry"
                if entry.is_numeric_qualifier
                else "names a principal that does not exist in this namespace"
            )
            findings.append(
                PermFinding(
                    facts.path,
                    check,
                    f"{where} {problem}",
                    "resolvable principals only",
                    f"{entry.label()} -> {resolution.label()}",
                    severity="medium",
                )
            )
    return findings


def verify(facts: PathFacts, policy: PathPolicy) -> list[PermFinding]:
    """Compare collected facts to a policy. Pure; touches no filesystem."""
    if not facts.exists:
        if policy.must_exist:
            return [
                PermFinding(
                    facts.path, "must_exist", "path does not exist", "present", "absent"
                )
            ]
        return []
    findings: list[PermFinding] = []
    if facts.is_symlink and policy.forbid_symlink:
        findings.append(
            PermFinding(
                facts.path, "forbid_symlink", "path is a symlink", "regular path",
                "symlink",
            )
        )
    findings.extend(_mode_findings(facts, policy))
    findings.extend(_ownership_findings(facts, policy))
    findings.extend(_acl_findings(facts, policy))
    return findings


def verify_path(
    path: str | os.PathLike[str], policy: PathPolicy, with_acl: bool = True
) -> list[PermFinding]:
    return verify(collect(path, with_acl=with_acl), policy)


def verify_tree(
    root: str | os.PathLike[str],
    policy: PathPolicy,
    with_acl: bool = True,
    skip_dirs: Iterable[str] = (".git", "node_modules", "__pycache__"),
) -> list[PermFinding]:
    """Apply one policy to every path under ``root``, deterministically."""
    skip = set(skip_dirs)
    start = os.fspath(root)
    findings = verify_path(start, policy, with_acl=with_acl)
    if not os.path.isdir(start):
        return findings
    for dirpath, dirnames, filenames in os.walk(start):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for name in sorted(dirnames) + sorted(filenames):
            findings.extend(
                verify_path(os.path.join(dirpath, name), policy, with_acl=with_acl)
            )
    return findings


SECRET_FILE_POLICY = PathPolicy(
    name="secret-file",
    mode_at_most=0o600,
    allow_world_readable=False,
    allow_world_writable=False,
    allow_group_writable=False,
)

SHARED_READONLY_POLICY = PathPolicy(
    name="shared-readonly",
    mode_at_most=0o750,
    allow_world_readable=False,
    allow_world_writable=False,
)


def _octal_mode(text: str) -> int:
    import argparse

    try:
        value = int(text, 8)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not an octal mode such as 750")
    if not 0 <= value <= 0o7777:
        raise argparse.ArgumentTypeError(f"{text!r} is outside 0..7777")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="guard-perm", description="Verify permissions and ACLs against a policy."
    )
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--mode-at-most", type=_octal_mode, help="octal ceiling, e.g. 750")
    parser.add_argument("--mode-exactly", type=_octal_mode, help="octal exact mode, e.g. 600")
    parser.add_argument("--owner")
    parser.add_argument("--group")
    parser.add_argument("--allow-world-readable", action="store_true")
    parser.add_argument("--allow-world-writable", action="store_true")
    parser.add_argument("--forbid-group-writable", action="store_true")
    parser.add_argument("--mask", dest="mask_exactly", help="e.g. r--")
    parser.add_argument("--require-default-acl", action="store_true")
    parser.add_argument("--forbid-unresolved-named", action="store_true")
    parser.add_argument(
        "--require-effective",
        action="append",
        default=[],
        metavar="KIND:QUALIFIER:PERMS",
        help="e.g. user:agent:r--",
    )
    parser.add_argument("--recursive", action="store_true")
    parser.add_argument("--no-acl", action="store_true")
    args = parser.parse_args(argv)

    required: list[tuple[str, str, str]] = []
    for spec in args.require_effective:
        parts = spec.split(":")
        if len(parts) != 3:
            parser.error(f"--require-effective expects KIND:QUALIFIER:PERMS, got {spec}")
        required.append((parts[0], parts[1], parts[2]))

    policy = PathPolicy(
        mode_exactly=args.mode_exactly,
        mode_at_most=args.mode_at_most,
        owner=args.owner,
        group=args.group,
        allow_world_readable=args.allow_world_readable,
        allow_world_writable=args.allow_world_writable,
        allow_group_writable=not args.forbid_group_writable,
        require_effective=tuple(required),
        mask_exactly=args.mask_exactly,
        require_default_acl=True if args.require_default_acl else None,
        forbid_unresolved_named=args.forbid_unresolved_named,
    )

    findings: list[PermFinding] = []
    for target in args.paths:
        if args.recursive:
            findings.extend(verify_tree(target, policy, with_acl=not args.no_acl))
        else:
            findings.extend(verify_path(target, policy, with_acl=not args.no_acl))
    for finding in findings:
        print(finding.format())
    print(f"{len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
