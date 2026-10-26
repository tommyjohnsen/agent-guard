# PROVENANCE (mirror of .provenance/ledger.jsonl; ledger wins)
# written-by: unknown (pre-provenance) | 2026-10-09 | f032f17
# modified-by: codex/gpt-5.6-sol | 2026-10-26 | 1aaa682 | provenance block added
# END PROVENANCE
"""Action policy gate.

Given a proposed action, refuse the risky classes and allow the rest, always
with a reason a human can act on.

Two design choices carry most of the value:

  * **Default deny on ambiguity is wrong here, and so is default allow.** An
    action that matches no rule is `ALLOW`, because the gate's job is to stop
    named risk classes rather than to whitelist all legitimate work. But an
    action whose *risk is recognised and whose authorisation cannot be
    established* returns `REVIEW`, a third outcome distinct from both. Folding
    `REVIEW` into `ALLOW` would let an unauthorised spend through; folding it
    into `DENY` would make the gate unusable for work that is merely sensitive.
  * **A caller-supplied identity is a claim, never an identity.** ``actor``
    and ``owner`` arrive from the same place as the rest of the request, so a
    forged pair used to make them match would authorise deleting anything. The
    gate therefore resolves the actor from the process (``os.getuid``) and
    ownership from the target's own inode (``os.lstat``), and treats the
    declared fields asymmetrically: a claim can make the outcome stricter but
    can never make it permissive. Allowing a delete requires a verified target
    whose owner uid equals the trusted uid; when ownership cannot be measured
    the answer is `REVIEW`, not `ALLOW`.
  * **Rules match on structure, not on prose.** Matching a free-text
    description would make the gate defeatable by rewording and would fire on
    any sentence that merely mentions money. Rules read declared fields -
    `kind`, `target`, `amount`, `principal` - and the text is used only as a
    secondary signal that can raise `REVIEW`, never to grant `ALLOW`.
"""

from __future__ import annotations

import grp
import os
import pwd
import re
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Callable, Iterable, Sequence


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REVIEW = "REVIEW"

    @property
    def permitted(self) -> bool:
        return self is Decision.ALLOW


class ActionKind(str, Enum):
    """Structured action classes the gate understands."""

    # Risky classes named by policy.
    SPEND = "spend"
    SEND_MESSAGE = "send_message"
    DELETE = "delete"
    ACTIVATE_SERVICE = "activate_service"
    ACCOUNT_CHANGE = "account_change"
    CREDENTIAL_CHANGE = "credential_change"
    # Ordinary classes.
    READ = "read"
    WRITE = "write"
    RUN_TESTS = "run_tests"
    BUILD = "build"
    COMMIT = "commit"
    PUSH = "push"
    INSTALL_DEV_DEPENDENCY = "install_dev_dependency"
    OTHER = "other"
    # Not a class a caller declares: what an unrecognised kind becomes, so an
    # unknown kind is refused rather than silently treated as ordinary work.
    UNKNOWN = "unknown"


def coerce_kind(value: object) -> ActionKind:
    """Normalise a declared kind, mapping anything unrecognised to UNKNOWN.

    Callers pass kinds from argv, JSON and other untyped sources. Accepting a
    bare string unchecked is what let ``kind="SPEND"`` fall through to ALLOW,
    so every value is resolved through the enum and failure is a value the
    rules can refuse, not an exception at an arbitrary call site.
    """
    if isinstance(value, ActionKind):
        return value
    if isinstance(value, str):
        try:
            return ActionKind(value.strip().lower())
        except ValueError:
            return ActionKind.UNKNOWN
    return ActionKind.UNKNOWN


RISKY_KINDS = frozenset(
    {
        ActionKind.SPEND,
        ActionKind.SEND_MESSAGE,
        ActionKind.DELETE,
        ActionKind.ACTIVATE_SERVICE,
        ActionKind.ACCOUNT_CHANGE,
        ActionKind.CREDENTIAL_CHANGE,
        # An unresolved kind is treated as risky, so even a gate built with no
        # rules at all refuses it through the fallthrough.
        ActionKind.UNKNOWN,
    }
)

# Principals the gate will never impersonate, unless configured otherwise.
# Override per gate with ``PolicyGate(protected_principals=...)``, for the
# process with the ``GUARD_PROTECTED_PRINCIPALS`` environment variable
# (comma-separated), or on the command line with ``--protect NAME``.
DEFAULT_PROTECTED_PRINCIPALS = frozenset({"owner", "root"})
PROTECTED_PRINCIPALS_ENV = "GUARD_PROTECTED_PRINCIPALS"
# Kept for callers that imported the old constant; it is the default set.
PROTECTED_PRINCIPALS = DEFAULT_PROTECTED_PRINCIPALS


def normalise_principals(names: Iterable[str]) -> frozenset[str]:
    """Lower-case, strip and drop empty names, so matching is case-insensitive."""
    return frozenset(n.strip().lower() for n in names if n and n.strip())


def protected_principals_from_env(environ=None) -> frozenset[str]:
    """The configured protected set: the environment variable if set, else the default.

    An empty or whitespace-only value is ignored rather than read as "protect
    nobody": switching the rule off has to be done explicitly in code.
    """
    raw = (os.environ if environ is None else environ).get(PROTECTED_PRINCIPALS_ENV, "")
    names = normalise_principals(raw.split(","))
    return names or DEFAULT_PROTECTED_PRINCIPALS

# Service managers whose activation is a live effect.
SERVICE_MANAGERS = frozenset(
    {"systemd", "systemctl", "launchd", "cron", "crontab", "timer", "init"}
)

_WORD = r"(?:^|[^a-z0-9])"


@dataclass(frozen=True)
class TrustedContext:
    """Identity the gate established for itself, not from the request.

    ``stat`` is injectable so the ownership rules can be exercised against a
    fixture tree without root and without changing any real file's owner.
    """

    uid: int
    username: str
    stat: Callable[[str], os.stat_result] = os.lstat
    # Operator configuration, never taken from a request.
    protected_principals: frozenset[str] = DEFAULT_PROTECTED_PRINCIPALS

    def __post_init__(self) -> None:
        # Matching is case-insensitive, so a context built by hand with
        # {"Alice"} must still protect "alice".
        object.__setattr__(
            self, "protected_principals", normalise_principals(self.protected_principals)
        )

    def names(self) -> frozenset[str]:
        """Spellings that denote this actor: its name and its numeric uid."""
        return frozenset({self.username.strip().lower(), str(self.uid)})

    def owner_of(self, path: str) -> "PathOwner":
        try:
            info = self.stat(path)
        except OSError as error:
            return PathOwner(None, None, error.strerror or type(error).__name__)
        return PathOwner(info.st_uid, _uid_name(info.st_uid), None)


@dataclass(frozen=True)
class PathOwner:
    """The measured owner of a path, or why it could not be measured."""

    uid: int | None
    username: str | None
    error: str | None

    @property
    def verified(self) -> bool:
        return self.uid is not None

    def label(self) -> str:
        if self.uid is None:
            return f"unverifiable ({self.error})"
        if self.username is None:
            return f"uid {self.uid} (unmapped)"
        return f"{self.username} (uid {self.uid})"


def _uid_name(uid: int) -> str | None:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def _gid_name(gid: int) -> str | None:  # pragma: no cover - parity helper
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return None


def resolve_trusted_context(
    protected_principals: Iterable[str] | None = None,
) -> TrustedContext:
    """Build the context from the running process and operator config, never from a request."""
    uid = os.getuid()
    protected = (
        normalise_principals(protected_principals)
        if protected_principals is not None
        else protected_principals_from_env()
    )
    return TrustedContext(
        uid=uid,
        username=_uid_name(uid) or str(uid),
        protected_principals=protected,
    )


@dataclass(frozen=True)
class Action:
    """A proposed action, described structurally.

    ``kind`` is the authoritative field. ``description`` is free text used only
    as a secondary signal, and ``extra`` carries anything a caller wants a rule
    to inspect without widening this class.
    """

    kind: ActionKind = ActionKind.OTHER
    description: str = ""
    target: str | None = None
    principal: str | None = None
    amount: float | None = None
    currency: str | None = None
    owner: str | None = None
    # A claimed actor. It is compared against the trusted identity and can
    # only ever tighten the outcome; it is never the basis for an allowance.
    actor: str | None = None
    authorized_by: str | None = None
    reversible: bool = True
    extra: dict[str, object] = field(default_factory=dict)
    # Set by __post_init__ to whatever the caller actually passed as ``kind``,
    # so a refusal can name the unrecognised value.
    declared_kind: object = None

    def __post_init__(self) -> None:
        declared = self.kind
        object.__setattr__(self, "kind", coerce_kind(declared))
        object.__setattr__(self, "declared_kind", declared)

    @property
    def text(self) -> str:
        parts = [self.description or "", self.target or ""]
        return " ".join(parts).lower()


@dataclass(frozen=True)
class Judgement:
    decision: Decision
    reason: str
    rule_id: str | None = None

    @property
    def permitted(self) -> bool:
        return self.decision.permitted

    def format(self) -> str:
        rule = f" [{self.rule_id}]" if self.rule_id else ""
        return f"{self.decision.value}{rule}: {self.reason}"


# A rule reads the action and the gate's own trusted identity, and returns a
# Judgement to stop evaluation or None to defer.
Rule = Callable[[Action, "TrustedContext"], "Judgement | None"]


def _mentions(text: str, *words: str) -> bool:
    return any(re.search(_WORD + re.escape(word), text) for word in words)


def rule_spend(action: Action, trusted: TrustedContext) -> Judgement | None:
    """Refuse anything that moves money."""
    money_text = _mentions(
        action.text,
        "purchase",
        "invoice",
        "subscribe",
        "subscription",
        "charge",
        "payment",
        "wire",
        "payout",
        "top-up",
        "billing",
    )
    if action.kind is ActionKind.SPEND or action.amount is not None or money_text:
        if action.kind is ActionKind.SPEND or action.amount is not None:
            detail = "spending money is refused"
            if action.amount is not None:
                currency = action.currency or "unspecified currency"
                detail = f"spending {action.amount} {currency} is refused"
            return Judgement(Decision.DENY, detail, "spend")
        return Judgement(
            Decision.REVIEW,
            "the request mentions payment but declares no spend; "
            "restate it structurally so it can be judged",
            "spend_ambiguous",
        )
    return None


def rule_send_as_protected_principal(action: Action, trusted: TrustedContext) -> Judgement | None:
    """Refuse sending messages, and never impersonate the owner."""
    principal = (action.principal or "").strip().lower()
    if principal in trusted.protected_principals:
        return Judgement(
            Decision.DENY,
            f"acting as {action.principal!r} is refused: the gate never "
            "impersonates the owner",
            "impersonation",
        )
    if action.kind is ActionKind.SEND_MESSAGE:
        return Judgement(
            Decision.DENY,
            "sending messages is refused; outbound communication is not this "
            "actor's to perform",
            "send_message",
        )
    if _mentions(action.text, "email", "slack", "sms", "dm", "message", "notify"):
        return Judgement(
            Decision.REVIEW,
            "the request looks like outbound communication but is not declared "
            "as one; restate it as kind=send_message to be judged",
            "send_message_ambiguous",
        )
    return None


def rule_delete_others_work(
    action: Action, trusted: TrustedContext
) -> Judgement | None:
    """Refuse deleting work that is not verifiably the trusted actor's own.

    The asymmetry is deliberate. A declared ``owner`` or ``actor`` that does
    not match the trusted identity is enough to refuse, because a claim can
    only tighten the outcome. Permitting a delete needs more than a claim: a
    target whose inode owner equals the trusted uid. Anything unmeasurable is
    ``REVIEW``.

    ``os.lstat`` is used rather than ``os.stat`` on purpose: removing a symlink
    removes the link, so the link's own owner is the one that governs.
    """
    if action.kind is not ActionKind.DELETE:
        return None
    trusted_names = trusted.names()
    declared_owner = (action.owner or "").strip().lower()
    declared_actor = (action.actor or "").strip().lower()

    if declared_owner and declared_owner not in trusted_names:
        return Judgement(
            Decision.DENY,
            f"deleting work owned by {action.owner!r} is refused; this gate "
            f"runs as {trusted.username!r} (uid {trusted.uid}) and may remove "
            "only its own work",
            "delete_others_work",
        )
    if declared_actor and declared_actor not in trusted_names:
        return Judgement(
            Decision.DENY,
            f"the request claims to act as {action.actor!r} but this gate runs "
            f"as {trusted.username!r} (uid {trusted.uid}); a declared actor is "
            "not an identity",
            "delete_actor_mismatch",
        )
    if not action.target:
        return Judgement(
            Decision.REVIEW,
            "a delete must name the target whose ownership can be checked; "
            "target is unset, so ownership rests on an unverified claim",
            "delete_target_unverifiable",
        )
    measured = trusted.owner_of(action.target)
    if not measured.verified:
        return Judgement(
            Decision.REVIEW,
            f"ownership of {action.target!r} could not be measured "
            f"({measured.error}); an unverifiable owner is not an allowance",
            "delete_owner_unverifiable",
        )
    if measured.uid != trusted.uid:
        return Judgement(
            Decision.DENY,
            f"{action.target!r} is owned by {measured.label()}, not by "
            f"{trusted.username!r} (uid {trusted.uid}); deleting another "
            "principal's work is refused",
            "delete_others_work",
        )
    if declared_owner and measured.username is not None and declared_owner not in (
        measured.username.strip().lower(),
        str(measured.uid),
    ):
        return Judgement(
            Decision.DENY,
            f"the request declares owner {action.owner!r} but {action.target!r} "
            f"is owned by {measured.label()}; the claim and the inode disagree",
            "delete_owner_claim_mismatch",
        )
    if not action.reversible:
        return Judgement(
            Decision.REVIEW,
            f"{action.target!r} is owned by {measured.label()} and may be "
            "removed, but this delete is declared irreversible; confirm first",
            "delete_irreversible",
        )
    return Judgement(
        Decision.ALLOW,
        f"{action.target!r} is owned by {measured.label()}, which is this "
        "gate's own identity, and the delete is reversible",
        "delete_own_work",
    )


def rule_activate_service(action: Action, trusted: TrustedContext) -> Judgement | None:
    """Refuse live activation: units, timers, wakes, daemon starts."""
    if action.kind is ActionKind.ACTIVATE_SERVICE:
        return Judgement(
            Decision.DENY,
            "live activation of services is refused",
            "activate_service",
        )
    target = (action.target or "").lower()
    manager = next((m for m in SERVICE_MANAGERS if m in target), None)
    if manager:
        return Judgement(
            Decision.DENY,
            f"the target names the {manager} service manager; units, timers "
            "and wakes are refused",
            "service_manager_target",
        )
    if _mentions(
        action.text, "systemctl", "systemd", "enable", "daemon", "timer", "wake"
    ):
        return Judgement(
            Decision.REVIEW,
            "the request mentions service activation; restate it structurally "
            "or scope it to a non-live action",
            "activate_ambiguous",
        )
    return None


def rule_account_or_credential_change(action: Action, trusted: TrustedContext) -> Judgement | None:
    """Refuse account and credential changes."""
    if action.kind is ActionKind.ACCOUNT_CHANGE:
        return Judgement(
            Decision.DENY, "account changes are refused", "account_change"
        )
    if action.kind is ActionKind.CREDENTIAL_CHANGE:
        return Judgement(
            Decision.DENY,
            "credential changes are refused, including rotation and revocation",
            "credential_change",
        )
    if _mentions(
        action.text,
        "password",
        "api key",
        "apikey",
        "token",
        "credential",
        "ssh key",
        "mfa",
        "2fa",
    ):
        return Judgement(
            Decision.REVIEW,
            "the request mentions credentials; restate it structurally so the "
            "gate can tell a read from a change",
            "credential_ambiguous",
        )
    return None


def rule_allow_ordinary_work(action: Action, trusted: TrustedContext) -> Judgement | None:
    """Permit the ordinary development classes explicitly."""
    ordinary = {
        ActionKind.READ: "reading files",
        ActionKind.WRITE: "writing files in the actor's own workspace",
        ActionKind.RUN_TESTS: "running tests",
        ActionKind.BUILD: "building",
        ActionKind.COMMIT: "committing to the actor's own branch",
        ActionKind.PUSH: "pushing the actor's own branch",
        ActionKind.INSTALL_DEV_DEPENDENCY: "installing a user-level dev dependency",
    }
    if action.kind in ordinary:
        return Judgement(Decision.ALLOW, ordinary[action.kind], "ordinary_work")
    return None


def rule_unknown_kind(action: Action, trusted: TrustedContext) -> Judgement | None:
    """Refuse an action whose kind did not resolve to a known class."""
    if action.kind is not ActionKind.UNKNOWN:
        return None
    return Judgement(
        Decision.DENY,
        f"{action.declared_kind!r} is not a known action kind; an action whose "
        "class cannot be determined is refused",
        "unknown_kind",
    )


DEFAULT_RULES: tuple[Rule, ...] = (
    # An unresolved kind is refused first: no later rule can reason about an
    # action whose class is unknown.
    rule_unknown_kind,
    # Impersonation and spend are checked before the ordinary-work allowance so
    # that a risky field cannot be smuggled in under a benign kind.
    rule_spend,
    rule_send_as_protected_principal,
    rule_account_or_credential_change,
    rule_activate_service,
    rule_delete_others_work,
    rule_allow_ordinary_work,
)


class PolicyGate:
    """Evaluates actions against an ordered rule list. First decision wins.

    ``trusted`` is resolved from the process at construction time. A caller
    may pass one explicitly - a test does, to exercise ownership rules against
    a fixture tree - but it is never taken from an ``Action``.
    """

    def __init__(
        self,
        rules: Sequence[Rule] | None = None,
        trusted: TrustedContext | None = None,
        protected_principals: Iterable[str] | None = None,
    ) -> None:
        self.rules: tuple[Rule, ...] = tuple(
            rules if rules is not None else DEFAULT_RULES
        )
        if trusted is None:
            trusted = resolve_trusted_context(protected_principals)
        elif protected_principals is not None:
            trusted = replace(
                trusted,
                protected_principals=normalise_principals(protected_principals),
            )
        self.trusted: TrustedContext = trusted

    def evaluate(self, action: Action) -> Judgement:
        for rule in self.rules:
            judgement = rule(action, self.trusted)
            if judgement is not None:
                return judgement
        if action.kind in RISKY_KINDS:  # pragma: no cover - defensive
            return Judgement(
                Decision.DENY,
                f"{action.kind.value} is a risky class with no explicit "
                "allowance",
                "risky_fallthrough",
            )
        return Judgement(
            Decision.ALLOW,
            "no policy rule objects to this action",
            "default_allow",
        )

    def check(self, action: Action) -> Judgement:
        """Alias for :meth:`evaluate`, for call sites that read better."""
        return self.evaluate(action)

    def permits(self, action: Action) -> bool:
        return self.evaluate(action).permitted

    def evaluate_all(self, actions: Iterable[Action]) -> list[Judgement]:
        return [self.evaluate(action) for action in actions]


_DEFAULT_GATE = PolicyGate()


def evaluate(action: Action) -> Judgement:
    """Evaluate against the default gate."""
    return _DEFAULT_GATE.evaluate(action)


def main(argv: Sequence[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog="guard-gate", description="Judge a proposed action against policy."
    )
    parser.add_argument("--kind", default="other", help="action kind")
    parser.add_argument("--description", default="")
    parser.add_argument("--target")
    parser.add_argument("--principal")
    parser.add_argument("--amount", type=float)
    parser.add_argument("--currency")
    parser.add_argument("--owner")
    # No default identity: an unstated actor is unstated, not "agent". The
    # gate resolves who it is from the process.
    parser.add_argument("--actor", default=None)
    parser.add_argument("--irreversible", action="store_true")
    parser.add_argument(
        "--protect",
        action="append",
        metavar="NAME",
        help="principal the gate must never act as (repeatable); replaces "
        f"the default set and ${PROTECTED_PRINCIPALS_ENV}",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    kind = coerce_kind(args.kind)
    if kind is ActionKind.UNKNOWN and args.kind.strip().lower() != ActionKind.UNKNOWN.value:
        parser.error(
            f"unknown --kind {args.kind!r}; choose from "
            + ", ".join(k.value for k in ActionKind)
        )

    action = Action(
        kind=kind,
        description=args.description,
        target=args.target,
        principal=args.principal,
        amount=args.amount,
        currency=args.currency,
        owner=args.owner,
        actor=args.actor,
        reversible=not args.irreversible,
    )
    gate = PolicyGate(protected_principals=args.protect) if args.protect else _DEFAULT_GATE
    judgement = gate.evaluate(action)
    if args.json:
        print(
            json.dumps(
                {
                    "decision": judgement.decision.value,
                    "rule_id": judgement.rule_id,
                    "reason": judgement.reason,
                }
            )
        )
    else:
        print(judgement.format())
    return {Decision.ALLOW: 0, Decision.REVIEW: 2, Decision.DENY: 1}[
        judgement.decision
    ]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
