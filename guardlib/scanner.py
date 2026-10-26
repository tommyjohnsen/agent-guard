# PROVENANCE (mirror of .provenance/ledger.jsonl; ledger wins)
# written-by: unknown (pre-provenance) | 2026-10-09 | f032f17
# modified-by: codex/gpt-5.6-sol | 2026-10-26 | 1aaa682 | restrict path exemption and add provenance block
# reviewed-by: claude-code/claude-opus-5-5 | 2026-10-26 | APPROVE_WITH_NITS
# END PROVENANCE
"""Secret and credential scanner.

Scans text, files and directory trees for private keys, API tokens, passwords,
.env-style assignments and high-entropy strings.

Design rules:
  * A finding never carries the full secret. ``Finding.redacted`` is a short
    fingerprint; the raw match is not stored on the finding at all.
  * Rules are data, so callers can add or drop them without editing the walker.
  * An inline ``guard:allow`` comment on the offending line suppresses it, so a
    repository can keep deliberate test fixtures without failing its own gate.
"""

from __future__ import annotations

import math
import os
import re
import stat
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Sequence

# Characters that can appear inside a token we would consider secret-shaped.
# ``=`` is base64 padding and only ever trails. Allowing it inside a token
# glued an assignment to its value, so ``rounding=ROUND_HALF_EVEN`` scored as
# one 24-character high-entropy string.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")
_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")
_BASE64ISH_RE = re.compile(r"\A[A-Za-z0-9+/=_\-]+\Z")

# ``guard:allow`` only suppresses when it appears in a comment. A bare
# occurrence inside a quoted string must not be able to silence the line, so
# comment starts are looked for outside quotes only, and ``//``, ``/*`` and
# ``--`` count only at the start of the line or after whitespace (a URL's
# ``https://`` is not a comment).
SUPPRESS_MARKER = "guard:allow"


def is_suppressed(line: str) -> bool:
    """True when ``guard:allow`` appears inside a comment on this line."""
    if SUPPRESS_MARKER not in line:
        return False
    quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch == "#":
            return SUPPRESS_MARKER in line[i:]
        elif line.startswith(("//", "/*", "--"), i) and (i == 0 or line[i - 1].isspace()):
            return SUPPRESS_MARKER in line[i:]
        i += 1
    return False

# A digest names content; it is not a credential, and its length says so.
# Exactly 40 or 64 hex characters is SHA-1 or SHA-256, and the Subresource
# Integrity form (``sha256-`` / ``sha384-`` / ``sha512-`` plus base64) is what
# npm lockfiles carry. Measured over one monorepo: 491 of 592 entropy findings were
# ``sha512-`` integrity values, so this is the dominant class, not a corner.
_HEX_DIGEST_RE = re.compile(r"\A(?:[0-9a-f]{40}|[0-9A-F]{40}|[0-9a-f]{64}|[0-9A-F]{64})\Z")
_SRI_DIGEST_RE = re.compile(r"\A(?:sha256|sha384|sha512)-[A-Za-z0-9+/]{20,}={0,2}\Z")


# A credential locator names where a secret lives; it is not the secret. The
# env:/file:/keyring: forms are how a config references a key without carrying
# it, and `"credential_ref": "env:ANTHROPIC_API_KEY"` was reported as a secret
# in a key/value mapping. The body must not itself be secret-shaped, so the
# prefix cannot become an escape hatch for `env:ghp_...`.
_LOCATOR_RE = re.compile(
    r"\A(?P<scheme>env|file|keyring|vault|secretref):(?P<body>[A-Za-z0-9._/-]{1,240})\Z"
)


# A locator body names a place: an environment variable, a path, or a
# service/entry pair. Each scheme gets the narrowest shape that admits real
# names, because the prefix is otherwise a way to carry bytes past the scanner.
_ENV_BODY_RE = re.compile(r"\A[A-Z][A-Z0-9_]{0,127}\Z")
_PATH_COMPONENT = r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
_PATH_BODY_RE = re.compile(rf"\A/?{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*\Z")
_LOCATOR_BODY_SHAPES = {
    "env": _ENV_BODY_RE,
    "file": _PATH_BODY_RE,
    "keyring": _PATH_BODY_RE,
    "vault": _PATH_BODY_RE,
    "secretref": _PATH_BODY_RE,
}
_LOCATOR_WORD_RE = re.compile(r"[A-Za-z0-9]+")


def _locator_body_is_opaque(body: str) -> bool:
    """True when the body carries bytes rather than naming a place.

    Entropy is measured here rather than taken from ``_entropy_findings``,
    which exempts anything ``_looks_like_identifier`` accepts -- and a
    camel-case random body is precisely that. A 24-character value scoring
    4.085 bits per character passed the whole pass on that exemption.

    Every test is per word -- a maximal run of letters and digits -- and never
    over the whole body. Scoring the body whole measures its separators: a path
    in this repository reaches 4.92 bits per character, and
    file:/var/lib/myservice/providers/local-llama/key was refused on that alone,
    as was keyring:providers/Qwen3-8B-Instruct.

    Shape covers what entropy cannot reach: per-character entropy is capped at
    ``log2(len)``, so a 16-character token never meets the 4.0 floor however
    random it is. A dense run of that length is read as a payload.

    What survives, measured rather than asserted: over 875 synthetic bodies of
    12 to 43 characters, 58 were still accepted, all of them 20 characters or
    shorter and none at 24 or above. A body whose words are each under 12
    characters, or under 16 with fewer than two character classes, is accepted
    and can carry roughly 70 bits. No shape test separates a 12-character name
    from a 12-character secret, so the per-scheme shapes and the named rules are
    the real limit here and this is the backstop.

    The cost is a known false positive: a single real name of 16 or more
    characters that mixes cases, such as a camel-case service id, is refused
    and reported. In a credential field that is a cheap review, and
    ``test_a_long_camel_case_name_is_a_known_false_positive`` pins it.
    """
    threshold = EntropyConfig().base64_bits
    for word in _LOCATOR_WORD_RE.findall(body):
        classes = sum(bool(re.search(cls, word)) for cls in (r"[a-z]", r"[A-Z]", r"[0-9]"))
        if len(word) >= 12 and classes == 3:
            return True
        if len(word) >= 16 and classes >= 2:
            return True
        if len(word) >= 16 and shannon_entropy(word) >= threshold:
            return True
    # A base64url blob carries - and _, so the word tests above see it in
    # pieces. Rejoining each path segment's words puts it back together, while a
    # real segment rejoins to something low-entropy or single-class:
    # local-llama to localllama, OPENAI_API_KEY to OPENAIAPIKEY. The 20
    # character floor keeps genuine mixed names such as Qwen3-8B-Instruct,
    # which rejoins to 15 characters, out of it.
    for segment in body.split("/"):
        joined = "".join(_LOCATOR_WORD_RE.findall(segment))
        classes = sum(bool(re.search(cls, joined)) for cls in (r"[a-z]", r"[A-Z]", r"[0-9]"))
        if len(joined) >= 20 and classes >= 2 and shannon_entropy(joined) >= threshold:
            return True
    return False


def is_credential_locator(value: str) -> bool:
    """True for a reference to a credential whose target is not itself a secret.

    The body is checked three ways. It must have the shape its scheme allows, it
    must not match a named rule, and it must not be opaque: before the last two,
    ``vault:`` followed by a high-entropy value was treated as benign in both the
    rule and the entropy paths, which made the prefix a place to hide a credential.
    """
    match = _LOCATOR_RE.match(value.strip())
    if match is None:
        return False
    body = match.group("body")
    shape = _LOCATOR_BODY_SHAPES.get(match.group("scheme"))
    if shape is None or not shape.match(body):
        return False
    if _locator_body_is_opaque(body):
        return False
    return not any(
        rule.rule_id != "dotenv_secret" and next(rule.secret_matches(body), None) is not None
        for rule in DEFAULT_RULES
    )


def is_digest_shaped(token: str) -> bool:
    """True for a value whose shape identifies it as a content digest."""
    return bool(_HEX_DIGEST_RE.match(token) or _SRI_DIGEST_RE.match(token))


# Values that read as source code rather than as a literal: a call, an
# attribute or subscript chain, or a type annotation. At least one of ``.``,
# ``(`` or ``[`` is required, so a bare identifier-shaped literal such as
# ``abc123def456`` is still a finding.
_CODE_EXPR_RE = re.compile(
    r"""\A
    [A-Za-z_$][A-Za-z0-9_$]*
    (?: \s*\.\s*[A-Za-z_$][A-Za-z0-9_$]* )*
    (?: \s*\[[^\]]*\]? )*
    (?: \s*\(.* )?
    [,;:]?
    \Z""",
    re.VERBOSE,
)


def is_code_expression(value: str) -> bool:
    """True for a call, an attribute/subscript access or a type annotation.

    A dotted chain alone is not enough: a JWT is three base64url segments
    joined by dots and matches the same grammar. Without a call or a
    subscript, every segment must also be word shaped, which ``eyJhbGciOi``
    is not and ``self.credentials.primary`` is.
    """
    stripped = value.strip()
    if not any(ch in stripped for ch in ".(["):
        return False
    if not _CODE_EXPR_RE.match(stripped):
        return False
    if "(" in stripped or "[" in stripped:
        return True
    return all(_is_word_segment(part) for part in stripped.rstrip(",;:").split("."))


# Marker words that make an all-capitals constant a stated placeholder rather
# than a value. The marker is required: without it an all-capitals token could
# be a real base32 secret.
_PLACEHOLDER_MARKERS = (
    "SECRET", "PAYLOAD", "EXAMPLE", "DUMMY", "SAMPLE", "FAKE", "TEST",
    "PLACEHOLDER", "REDACTED", "CHANGEME", "TODO", "SYNTHETIC", "FIXTURE",
)
_SCREAMING_RE = re.compile(r"\A[A-Z][A-Z0-9]*(?:[-_][A-Z0-9]+)*\Z")


def is_screaming_placeholder(value: str) -> bool:
    """True for ``SECRET-BYTE-PAYLOAD`` style declared placeholders.

    The marker must be a whole ``-`` or ``_`` segment. As a substring it
    swallowed real values: ``SUPERSECRETVALUE123`` contains SECRET and an AWS
    id whose body happens to contain TEST contains TEST, and both are secrets.
    """
    stripped = value.strip()
    if not _SCREAMING_RE.match(stripped):
        return False
    return any(segment in _PLACEHOLDER_MARKERS for segment in re.split(r"[-_]", stripped))

# Identifiers and paths score above the base64 entropy floor, and raising the
# floor cannot separate them: measured over this repository's docs/ and
# packages/, a path scores up to 4.92 bits per character while a real GitLab
# token scores 4.62. The discriminator has to be shape, not entropy.
#
# A "word segment" is a camelCase/PascalCase identifier, an acronym, or a
# number. Each hump must carry a lowercase run or be a 2+ letter acronym, so
# base64 such as "aGVsbG8" (single capitals between lowercase runs) is not a
# word segment and stays eligible.
_WORD_SEGMENT_RE = re.compile(
    r"\A(?:[a-z]+|[A-Z][a-z]+|[A-Z]{2,})(?:[A-Z][a-z]+|[A-Z]{2,}|[0-9]+)*[0-9]*\Z"
)
# Fraction of a separated token's characters that must be word segments before
# the token is read as an identifier rather than a credential.
IDENT_COVERAGE = 0.6

# Directories that are never worth walking.
DEFAULT_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".tox",
    }
)

# Suffixes that are binary or generated often enough to skip by default.
DEFAULT_SKIP_SUFFIXES = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".pdf",
        ".zip",
        ".gz",
        ".bz2",
        ".xz",
        ".tar",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".so",
        ".dylib",
        ".dll",
        ".class",
        ".jar",
        ".pyc",
        ".wasm",
        ".mp4",
        ".mp3",
        ".lock",
    }
)

# Built output is skipped by default because it is derived and usually large,
# but it is also exactly where an environment value gets baked into a bundle,
# so there is one flag to put it back rather than a config rewrite.
BUILD_OUTPUT_DIRS = frozenset({"dist", "build"})

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 8 * 1024
# A minified JSON or JSONL line can carry a secret far past the window, so a
# long line is scanned in overlapping windows rather than truncated. The
# overlap is the longest single-line secret we expect to reassemble.
LINE_CHUNK_OVERLAP = 2 * 1024


@dataclass(frozen=True)
class Rule:
    """A named detector.

    ``group`` selects which capture group holds the sensitive span, so the
    redaction covers the secret rather than the surrounding assignment syntax.
    """

    rule_id: str
    description: str
    pattern: re.Pattern[str]
    severity: str = "high"
    group: int = 0
    # Mapping-style rules match source code as readily as configuration, where
    # the value is a variable rather than a literal. Set this to drop values
    # that are plainly code identifiers.
    skip_code_values: bool = False
    # True when the capture can only ever be a credential, such as the
    # password component of a URL. No shape exemption applies to it.
    literal_credential: bool = False

    def secret_matches(self, line: str) -> Iterator[tuple[int, str]]:
        """Yield ``(start, value)`` for each hit, start being a line offset."""
        for match in self.pattern.finditer(line):
            try:
                value = match.group(self.group)
                start = match.start(self.group)
            except IndexError:  # pragma: no cover - misconfigured rule
                value, start = match.group(0), match.start(0)
            if value:
                yield start, value

    def secret_spans(self, line: str) -> Iterator[str]:
        for _, value in self.secret_matches(line):
            yield value


@dataclass(frozen=True)
class Finding:
    """One detection. Deliberately carries no raw secret."""

    path: str
    line: int
    rule_id: str
    description: str
    redacted: str
    severity: str = "high"

    def format(self) -> str:
        return (
            f"{self.path}:{self.line}: [{self.severity}] {self.rule_id}: "
            f"{self.description} ({self.redacted})"
        )


def redact(secret: str) -> str:
    """Return a fingerprint that identifies a secret without disclosing it.

    Short values get no prefix at all, because four characters of an
    eight-character password is already most of it.
    """
    length = len(secret)
    if length <= 8:
        return f"<redacted len={length}>"
    return f"{secret[:4]}...<redacted len={length}>"


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character, over the value's own symbol distribution."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    return -sum(
        (count / total) * math.log2(count / total) for count in counts.values()
    )


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# Keyword fragment shared by the assignment-style rules.
_SECRET_KEY = (
    r"(?:secret|token|password|passwd|pwd|api[_-]?key|apikey|access[_-]?key"
    r"|private[_-]?key|credential|client[_-]?secret|auth[_-]?token)"
)

DEFAULT_RULES: tuple[Rule, ...] = (
    Rule(
        "private_key_block",
        "PEM private key block",
        _compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
        "critical",
    ),
    Rule(
        "aws_access_key_id",
        "AWS access key id",
        _compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "critical",
        group=1,
    ),
    Rule(
        "github_pat",
        "GitHub personal access token",
        _compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"),
        "critical",
        group=1,
    ),
    Rule(
        "github_fine_grained_pat",
        "GitHub fine-grained token",
        _compile(r"\b(github_pat_[A-Za-z0-9_]{20,})\b"),
        "critical",
        group=1,
    ),
    Rule(
        "slack_token",
        "Slack token",
        _compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
        "critical",
        group=1,
    ),
    Rule(
        "anthropic_api_key",
        "Anthropic API key",
        _compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"),
        "critical",
        group=1,
    ),
    Rule(
        "openai_api_key",
        "OpenAI-style API key",
        _compile(r"\b(sk-(?!ant-)[A-Za-z0-9_\-]{20,})\b"),
        "critical",
        group=1,
    ),
    Rule(
        "google_api_key",
        "Google API key",
        _compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
        "critical",
        group=1,
    ),
    Rule(
        "jwt",
        "JSON Web Token",
        _compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"),
        "high",
        group=1,
    ),
    Rule(
        "bearer_token",
        "Authorization bearer token",
        _compile(r"[Bb]earer\s+([A-Za-z0-9._\-+/=]{20,})"),
        "high",
        group=1,
    ),
    Rule(
        "dotenv_secret",
        "env-style secret assignment",
        _compile(
            rf"^\s*(?:export\s+)?[A-Za-z0-9_]*{_SECRET_KEY}[A-Za-z0-9_]*\s*=\s*"
            r"['\"]?([^'\"\s#]{6,})['\"]?",
            re.IGNORECASE | re.MULTILINE,
        ),
        "high",
        group=1,
    ),
    Rule(
        "password_assignment",
        "password assigned in code",
        _compile(
            rf"""{_SECRET_KEY}\s*[:=]\s*['"]([^'"\s]{{6,}})['"]""",
            re.IGNORECASE,
        ),
        "high",
        group=1,
    ),
    Rule(
        "mapping_secret",
        "secret in a key/value mapping",
        _compile(
            rf"^[\s\-\"']*(?:[A-Za-z0-9_]*{_SECRET_KEY}[A-Za-z0-9_]*)[\"']?\s*:\s*"
            r"['\"]?([^'\"\s,#][^'\"\s,]{7,})['\"]?\s*,?\s*$",
            re.IGNORECASE | re.MULTILINE,
        ),
        "high",
        group=1,
        skip_code_values=True,
    ),
    Rule(
        "stripe_live_key",
        "Stripe live secret or restricted key",
        _compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{16,})\b"),
        "critical",
        group=1,
    ),
    Rule(
        "gitlab_pat",
        "GitLab personal access token",
        _compile(r"\b(glpat-[0-9A-Za-z_\-]{20,})\b"),
        "critical",
        group=1,
    ),
    Rule(
        "npm_token",
        "npm access token",
        _compile(r"\b(npm_[0-9A-Za-z]{36})\b"),
        "critical",
        group=1,
    ),
    Rule(
        "huggingface_token",
        "Hugging Face access token",
        _compile(r"\b(hf_[0-9A-Za-z]{30,})\b"),
        "critical",
        group=1,
    ),
    Rule(
        "url_embedded_credential",
        "credential embedded in URL",
        _compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:([^/\s:@]{3,})@"),
        "high",
        group=1,
        literal_credential=True,
    ),
)

# Placeholder values that are conventionally not secrets.
_PLACEHOLDERS = frozenset(
    {
        "changeme",
        "change_me",
        "password",
        "secret",
        "example",
        "placeholder",
        "redacted",
        "xxxxxx",
        "your_token_here",
        "user",
        "pass",
        "passwd",
        "username",
        "test",
        "dummy",
        "sample",
        "fake",
        "none",
        "null",
        "true",
        "false",
    }
)


def is_benign_value(value: str, *, quoted: bool, credential_position: bool) -> bool:
    """True for shapes that are never a secret *in this position*.

    Position is what makes an exemption safe. Applying these shapes to every
    capture regardless of position dropped real secrets:

    * ``credential_position`` is a capture that can only ever be a credential,
      such as the password in a URL. No shape exemption applies there; only an
      exact placeholder value does. ``https://admin:TEST-ADMIN-TOKEN@host``
      and ``https://admin:Correct.Horse.Battery@host`` are secrets.
    * ``quoted`` means the capture came from inside a string literal, so it is
      not a source expression however much it looks like one.
      ``password = "lookup(seedvalue123)"`` and
      ``password = "Abcdefghij.Klmnopqrst.Uvwxyzabcd"`` are secrets.
    * A digest shape is deliberately absent. 40 and 64 hex characters are
      exempt only in the entropy pass, where length is the whole signal;
      ``API_KEY=<64 hex>`` is still an assigned secret. The Subresource
      Integrity shape is entropy-only for the same reason, so
      ``password = "sha256-<base64>"`` reports.
    """
    stripped = value.strip()
    if credential_position:
        return False
    if is_screaming_placeholder(stripped):
        return True
    if is_credential_locator(stripped):
        return True
    if quoted:
        return False
    return is_code_expression(stripped)


def _is_code_value(
    value: str, *, quoted: bool, credential_position: bool
) -> bool:
    """True when a captured value is not a literal secret.

    Four shapes, each measured against real false positives:

    * a code expression - ``record.get("tokens")``, ``_tokens(record,``,
      ``list[int]`` - which is a call, an access or a type annotation;
    * an identifier or member name - ``assignment.credential``,
      ``max_tokens: maxTokens`` - where every segment is word shaped;
    * a content digest, by length or by Subresource Integrity prefix;
    * a declared all-capitals placeholder such as ``SECRET-BYTE-PAYLOAD``.

    The segment rule is what separates an identifier from a literal:
    ``abc123def456`` and ``s3cr3tValue123`` are not word segments, and
    anything containing a slash is never treated as a bare identifier.
    """
    if is_benign_value(value, quoted=quoted, credential_position=credential_position):
        return True
    if credential_position:
        return False
    trimmed = value.strip().rstrip("(){}[],;")
    if not trimmed or "/" in trimmed:
        return False
    # A quoted dotted literal is not a member expression.
    if quoted and "." in trimmed:
        return False
    return all(_is_word_segment(seg) for seg in re.split(r"[.\-_]", trimmed))


def _is_word_segment(segment: str) -> bool:
    if segment == "" or segment.isdigit():
        return True
    return bool(_WORD_SEGMENT_RE.match(segment))


def _looks_like_identifier(token: str) -> bool:
    """True for identifiers and filesystem paths, which are not credentials.

    Three tests, in order of how much of the corpus they explain:

    * An explicit filesystem prefix is a path. Relative strings with two or
      more slashes still have to pass the word-segment coverage test below;
      Base64 credentials can contain multiple slashes too.
    * A single camelCase or PascalCase word is an identifier.
    * A separated token whose word segments cover ``IDENT_COVERAGE`` of its
      characters is an identifier with an opaque part, such as a temp-directory
      suffix. The coverage floor is what keeps a real token out: ``sk_live_``
      and ``npm_`` prefixes cover under a fifth of their token's characters.
    """
    if token.startswith(("/", "./", "../", "~/")):
        return True
    segments = re.split(r"[-/_.]", token)
    if len(segments) < 3:
        return _is_word_segment(token)
    covered = sum(len(seg) for seg in segments if _is_word_segment(seg))
    return covered >= IDENT_COVERAGE * len(token)


def _is_placeholder(value: str) -> bool:
    stripped = value.strip().strip("<>{}[]()")
    lowered = stripped.lower()
    if lowered in _PLACEHOLDERS:
        return True
    # ${VAR}, $VAR and {{ var }} interpolation are not literals. A leading
    # dollar alone is not enough: a bcrypt hash ($2b$12$...) and a password
    # that merely starts with "$" are both real secrets.
    if re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", stripped):
        return True
    if stripped.startswith("{{"):
        return True
    if re.fullmatch(r"[xX*\.\-_]+", stripped):
        return True
    return False


@dataclass
class EntropyConfig:
    """Thresholds for the generic high-entropy detector.

    Pure hex digests are excluded by default: a repository that records SHA-256
    values everywhere would otherwise drown in findings, and a digest is not a
    credential. Set ``flag_hex`` to include them.
    """

    enabled: bool = True
    min_length: int = 24
    base64_bits: float = 4.0
    hex_bits: float = 3.2
    flag_hex: bool = False
    min_hex_length: int = 32


@dataclass
class ScanConfig:
    rules: Sequence[Rule] = field(default=DEFAULT_RULES)
    entropy: EntropyConfig = field(default_factory=EntropyConfig)
    skip_dirs: frozenset[str] = DEFAULT_SKIP_DIRS
    skip_suffixes: frozenset[str] = DEFAULT_SKIP_SUFFIXES
    max_file_bytes: int = MAX_FILE_BYTES
    follow_symlinks: bool = False
    honor_suppressions: bool = True


@dataclass
class ScanStats:
    """Counters and problems accumulated alongside the findings.

    ``errors`` is what separates "clean" from "did not look". A scanner that
    reports zero findings for a path it never read is worse than one that
    fails, because the zero is indistinguishable from a real pass.
    """

    files_scanned: int = 0
    lines_scanned: int = 0
    suppressed_lines: int = 0
    skipped_unreadable: int = 0
    skipped_oversize: int = 0
    skipped_binary: int = 0
    skipped_symlinks: int = 0
    # Directories not walked, by name, with how many times each was skipped.
    # A skipped directory is a policy choice rather than a failure, so it does
    # not make a scan incomplete - but it must be named, because silence over
    # an unwalked tree reads exactly like coverage.
    skipped_dirs: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def incomplete(self) -> bool:
        """True when some part of the requested scope was not examined."""
        return bool(self.errors) or bool(
            self.skipped_unreadable or self.skipped_oversize
        )

    def record_skipped_dir(self, name: str) -> None:
        self.skipped_dirs[name] = self.skipped_dirs.get(name, 0) + 1

    def record_error(self, path: str, problem: str) -> None:
        self.errors.append(f"{path}: {problem}")

    def summary(self) -> str:
        return (
            f"{self.files_scanned} file(s) scanned, "
            f"{self.suppressed_lines} line(s) suppressed by {SUPPRESS_MARKER}, "
            f"{self.skipped_unreadable} unreadable, "
            f"{self.skipped_oversize} oversize, "
            f"{self.skipped_binary} binary, "
            f"{self.skipped_symlinks} symlink(s) skipped, "
            f"{self.skipped_directories} director(ies) not walked"
            f"{self.skipped_dirs_note}, "
            f"{len(self.errors)} error(s)"
        )

    @property
    def skipped_directories(self) -> int:
        return sum(self.skipped_dirs.values())

    @property
    def skipped_dirs_note(self) -> str:
        """The skipped directory names, so a reader can see what was not read."""
        if not self.skipped_dirs:
            return ""
        names = ", ".join(f"{n}x{c}" if c > 1 else n for n, c in sorted(self.skipped_dirs.items()))
        return f" ({names})"


def _entropy_findings(
    line: str, path: str, lineno: int, config: EntropyConfig, accept: int
) -> Iterator[Finding]:
    if not config.enabled:
        return
    for match in _TOKEN_RE.finditer(line):
        if match.start(0) >= accept:
            continue
        token = match.group(0)
        if len(token) < config.min_length:
            continue
        if _is_placeholder(token) or _looks_like_identifier(token):
            continue
        # A digest is skipped even under --flag-hex: its length, not the
        # setting, is what says it names content rather than authorises.
        if is_digest_shaped(token):
            continue
        is_hex = bool(_HEX_RE.match(token))
        if is_hex:
            if not config.flag_hex or len(token) < config.min_hex_length:
                continue
            threshold = config.hex_bits
            rule_id = "high_entropy_hex"
            description = "high-entropy hex string"
        else:
            if not _BASE64ISH_RE.match(token):
                continue
            # Require a mix of classes; a long lowercase word is not a secret.
            classes = sum(
                bool(re.search(cls, token))
                for cls in (r"[a-z]", r"[A-Z]", r"[0-9]")
            )
            if classes < 2:
                continue
            threshold = config.base64_bits
            rule_id = "high_entropy_base64"
            description = "high-entropy token"
        if shannon_entropy(token) >= threshold:
            yield Finding(
                path=path,
                line=lineno,
                rule_id=rule_id,
                description=description,
                redacted=redact(token),
                severity="medium",
            )


def line_chunks(line: str) -> Iterator[tuple[str, int]]:
    """Yield ``(chunk, accept)`` windows covering ``line``.

    ``accept`` is the offset within the chunk past which a match belongs to the
    next window. Every position of the line therefore starts a match in exactly
    one window, so the overlap cannot report a secret twice, while a secret
    straddling a window edge is still seen whole by the following window.
    """
    if len(line) <= MAX_LINE_BYTES:
        yield line, len(line)
        return
    step = MAX_LINE_BYTES - LINE_CHUNK_OVERLAP
    start = 0
    while start < len(line):
        chunk = line[start : start + MAX_LINE_BYTES]
        last = start + MAX_LINE_BYTES >= len(line)
        yield chunk, len(chunk) if last else step
        if last:
            return
        start += step


def scan_text(
    text: str,
    path: str = "<text>",
    config: ScanConfig | None = None,
    stats: ScanStats | None = None,
) -> list[Finding]:
    """Scan in-memory text. Returns findings ordered by line, then rule id."""
    cfg = config or ScanConfig()
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if stats is not None:
            stats.lines_scanned += 1
        if cfg.honor_suppressions and is_suppressed(line):
            if stats is not None:
                stats.suppressed_lines += 1
            continue
        seen: set[tuple[str, str]] = set()
        for chunk, accept in line_chunks(line):
            for rule in cfg.rules:
                for start, secret in rule.secret_matches(chunk):
                    if start >= accept:
                        continue
                    if _is_placeholder(secret):
                        continue
                    # A capture immediately preceded by a quote came from a
                    # string literal, which is never a source expression.
                    quoted = start > 0 and chunk[start - 1] in "'\""
                    position = {
                        "quoted": quoted,
                        "credential_position": rule.literal_credential,
                    }
                    if is_benign_value(secret, **position):
                        continue
                    if rule.skip_code_values and _is_code_value(secret, **position):
                        continue
                    key = (rule.rule_id, secret)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        Finding(
                            path=path,
                            line=lineno,
                            rule_id=rule.rule_id,
                            description=rule.description,
                            redacted=redact(secret),
                            severity=rule.severity,
                        )
                    )
            for finding in _entropy_findings(
                chunk, path, lineno, cfg.entropy, accept
            ):
                # Do not double-report a span a named rule already caught.
                if any(
                    existing.line == finding.line
                    and existing.redacted == finding.redacted
                    for existing in findings
                ):
                    continue
                findings.append(finding)
    findings.sort(key=lambda f: (f.line, f.rule_id))
    return findings


def _looks_binary(blob: bytes) -> bool:
    if b"\x00" in blob:
        return True
    if not blob:
        return False
    # Heuristic: a high share of bytes outside printable/UTF-8 continuation.
    printable = sum(
        1 for byte in blob if byte in (9, 10, 13) or 32 <= byte < 127 or byte >= 128
    )
    return (printable / len(blob)) < 0.85


def scan_file(
    path: str | os.PathLike[str],
    config: ScanConfig | None = None,
    stats: ScanStats | None = None,
) -> list[Finding]:
    """Scan a single file. Unreadable, oversized and binary files yield nothing."""
    cfg = config or ScanConfig()
    name = os.fspath(path)
    try:
        if os.path.islink(name) and not cfg.follow_symlinks:
            if stats is not None:
                stats.skipped_symlinks += 1
            return []
        size = os.path.getsize(name)
    except OSError as error:
        if stats is not None:
            stats.skipped_unreadable += 1
            stats.record_error(name, error.strerror or type(error).__name__)
        return []
    if size > cfg.max_file_bytes:
        if stats is not None:
            stats.skipped_oversize += 1
            stats.record_error(name, f"{size} bytes exceeds the scan limit")
        return []
    if os.path.splitext(name)[1].lower() in cfg.skip_suffixes:
        return []
    try:
        with open(name, "rb") as handle:
            blob = handle.read(cfg.max_file_bytes)
    except OSError as error:
        if stats is not None:
            stats.skipped_unreadable += 1
            stats.record_error(name, error.strerror or type(error).__name__)
        return []
    if _looks_binary(blob[:4096]):
        if stats is not None:
            stats.skipped_binary += 1
        return []
    text = blob.decode("utf-8", errors="replace")
    if stats is not None:
        stats.files_scanned += 1
    return scan_text(text, path=name, config=cfg, stats=stats)


def validate_root(
    root: str | os.PathLike[str], config: ScanConfig | None = None
) -> str | None:
    """Return why ``root`` cannot be scanned, or None when it can.

    ``os.lstat`` rather than ``os.stat``: a symlinked root would otherwise be
    traversed even with ``follow_symlinks=False``, which is the opposite of
    what that setting asks for, and a dangling link would read as "missing"
    rather than as a link.
    """
    cfg = config or ScanConfig()
    name = os.fspath(root)
    try:
        info = os.lstat(name)
    except OSError as error:
        return error.strerror or type(error).__name__
    if stat.S_ISLNK(info.st_mode):
        if not cfg.follow_symlinks:
            return "symlinked root not followed (follow_symlinks is off)"
        # Opted in: judge the type of what the link points at, and report a
        # dangling link as the resolution failure it is.
        try:
            info = os.stat(name)
        except OSError as error:
            return error.strerror or type(error).__name__
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        return "not a regular file or directory"
    return None


def scan_path(
    root: str | os.PathLike[str],
    config: ScanConfig | None = None,
    stats: ScanStats | None = None,
) -> list[Finding]:
    """Scan a file or walk a directory tree. Deterministic ordering.

    The root is validated before anything is walked. A missing path, a path of
    the wrong type, and a symlinked root are each recorded on ``stats`` and
    yield no findings - and ``stats.errors`` is how a caller tells that apart
    from a clean scan. ``validate_root`` is the same check, usable on its own.
    """
    cfg = config or ScanConfig()
    start = os.fspath(root)
    problem = validate_root(start, cfg)
    if problem is not None:
        if stats is not None:
            stats.record_error(start, problem)
        return []
    if os.path.isfile(start):
        return scan_file(start, cfg, stats)
    findings: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(start, followlinks=cfg.follow_symlinks):
        kept = []
        for name in sorted(dirnames):
            if name in cfg.skip_dirs:
                if stats is not None:
                    stats.record_skipped_dir(name)
                continue
            kept.append(name)
        dirnames[:] = kept
        for filename in sorted(filenames):
            findings.extend(scan_file(os.path.join(dirpath, filename), cfg, stats))
    return findings


def worst_severity(findings: Iterable[Finding]) -> str | None:
    order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    worst: str | None = None
    for finding in findings:
        if worst is None or order.get(finding.severity, 0) > order.get(worst, 0):
            worst = finding.severity
    return worst


def main(argv: Sequence[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="guard-scan", description="Scan for secrets and credentials."
    )
    parser.add_argument("paths", nargs="+", help="files or directories to scan")
    parser.add_argument(
        "--no-entropy", action="store_true", help="disable the entropy detector"
    )
    parser.add_argument(
        "--flag-hex", action="store_true", help="also flag high-entropy hex strings"
    )
    parser.add_argument(
        "--scan-build-output",
        action="store_true",
        help=f"also walk {', '.join(sorted(BUILD_OUTPUT_DIRS))}, which are skipped by default",
    )
    parser.add_argument(
        "--ignore-suppressions",
        action="store_true",
        help="report lines marked guard:allow",
    )
    args = parser.parse_args(argv)

    skip_dirs = DEFAULT_SKIP_DIRS
    if args.scan_build_output:
        skip_dirs = frozenset(skip_dirs - BUILD_OUTPUT_DIRS)
    config = ScanConfig(
        entropy=EntropyConfig(
            enabled=not args.no_entropy, flag_hex=args.flag_hex
        ),
        skip_dirs=skip_dirs,
        honor_suppressions=not args.ignore_suppressions,
    )
    findings: list[Finding] = []
    stats = ScanStats()
    for target in args.paths:
        findings.extend(scan_path(target, config, stats))
    for finding in findings:
        print(finding.format())
    print(f"{len(findings)} finding(s); {stats.summary()}")
    for problem in stats.errors:
        print(f"error: {problem}", file=sys.stderr)
    # An incomplete scan outranks a clean one: zero findings over a path that
    # was never read must not exit 0.
    if stats.incomplete:
        print(
            f"scan incomplete: {len(stats.errors)} path(s) could not be read",
            file=sys.stderr,
        )
        return 2
    return 1 if findings else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
