<!--
PROVENANCE (mirror of .provenance/ledger.jsonl; ledger wins)
written-by: unknown (pre-provenance) | 2026-10-09 | f032f17
modified-by: codex/gpt-5.6-sol | 2026-10-26 | pending | provenance block added
END PROVENANCE
-->
# agent-guard

Three small, dependency-free safety tools for automation and AI agents:

- **`guard-scan`**: a secret and credential scanner for text, files and directory trees.
- **`guard-perm`**: a filesystem permission and POSIX ACL verifier that understands mask clipping.
- **`guard-gate`**: an action policy gate that returns `ALLOW`, `DENY` or `REVIEW` for a proposed action, with a reason a human can act on.

Pure Python standard library, Python 3.10+. No network access and no root needed. `guard-perm` calls the read-only `getfacl` when it's installed and falls back to mode bits when it isn't.

## Install

```
pip install .
```

Or run from a checkout without installing: `python3 -m guardlib.scanner PATH`, `python3 -m guardlib.permcheck PATH`, `python3 -m guardlib.gate ...`.

## guard-scan: secret scanner

```
$ guard-scan .
./config/app.env:1: [high] dotenv_secret: env-style secret assignment (s3cr...<redacted len=14>)
1 finding(s); 41 file(s) scanned, 0 line(s) suppressed by guard:allow, ...
```

- Detects private key blocks, provider token shapes (AWS, GitHub, GitLab, Slack, Stripe, npm, Hugging Face, Google, Anthropic and others), `.env`-style and code assignments, credentials embedded in URLs, and high-entropy strings.
- **A finding never contains the secret.** It carries a short prefix and the length only, so scan output is safe to paste into logs and CI.
- The entropy pass is tuned against real false positives: file paths, identifiers, digests, Subresource Integrity hashes and credential *locators* such as `env:API_KEY` or `vault:kv/app/db`.
- Add `guard:allow` in a comment on a line to suppress it (for deliberate test fixtures). The marker counts only inside a comment (`#`, or `//`, `/*`, `--` after whitespace), never inside a quoted string. `--ignore-suppressions` shows suppressed lines anyway.
- Exits 1 when anything is found, so it can gate a pre-commit hook or CI job.
- Options: `--no-entropy`, `--flag-hex`, `--scan-build-output`, `--ignore-suppressions`.

As a library:

```python
from guardlib import scanner

for finding in scanner.scan_text(open("settings.py").read()):
    print(finding.format())
```

## guard-perm: permission and ACL verifier

```
$ guard-perm --mode-at-most 750 --forbid-group-writable --recursive /var/www/app
$ guard-perm --mode-exactly 600 --owner deploy ~/.ssh/id_ed25519
$ guard-perm --require-effective user:agent:r-- --mask r-- /data/shared
```

- Checks mode bits, owner and group, setuid/setgid, world-readable and world-writable exposure, named ACL entries, the ACL mask and default ACLs.
- **Mask clipping is applied.** A named entry `user:agent:rwx` under `mask::---` grants nothing. `--require-effective` checks what the entry actually allows, not what it says.
- Parsing (`parse_getfacl`), fact collection (`collect`) and policy comparison (`verify`) are separate, so every rule can be tested from `getfacl` text fixtures without changing real files.
- Exits 1 when any path breaks the policy.

## guard-gate: action policy gate

```
$ guard-gate --kind read
ALLOW [ordinary_work]: reading files
$ guard-gate --kind spend --amount 20 --currency USD
DENY [spend]: spending 20.0 USD is refused
$ guard-gate --kind delete --target ./build/output.log
ALLOW [delete_own_work]: './build/output.log' is owned by me (uid 1000), which is this gate's own identity, and the delete is reversible
$ guard-gate --kind write --principal owner --json
{"decision": "DENY", "rule_id": "impersonation", "reason": "acting as 'owner' is refused: the gate never impersonates the owner"}
```

Exit codes: `0` ALLOW, `1` DENY, `2` REVIEW.

Refused classes: spending money, sending messages, deleting other people's work, activating services (systemd, launchd, cron and similar), account or credential changes, unknown action kinds, and acting as a protected principal.

Protected principals default to `owner` and `root` and are matched case-insensitively. To change them:

```
export GUARD_PROTECTED_PRINCIPALS="alice,ops-lead"      # process-wide
guard-gate --kind write --principal alice --protect alice   # per call; replaces the set
```

```python
from guardlib.gate import Action, ActionKind, PolicyGate

gate = PolicyGate(protected_principals={"alice", "root"})
judgement = gate.evaluate(Action(kind=ActionKind.DELETE, target="/tmp/report.csv"))
print(judgement.decision, judgement.reason)
```

## Security model

- **Three outcomes, not two.** An action that matches no rule is `ALLOW`, because the gate exists to stop named risk classes, not to whitelist all work. An action whose risk is recognised but whose authorisation can't be established is `REVIEW`. Folding `REVIEW` into `ALLOW` would let an unauthorised spend through. Folding it into `DENY` would make the gate unusable for work that's merely sensitive.
- **A caller-supplied identity is a claim, not an identity.** The gate takes the acting user from the process (`os.getuid`) and a file's owner from the file itself (`os.lstat`). Declared `actor` and `owner` fields can make a decision stricter but never more permissive. A delete is allowed only when the target's owner uid matches the process uid. If ownership can't be measured, the answer is `REVIEW`.
- **Rules read structure, not prose.** Decisions come from declared fields (`kind`, `target`, `amount`, `principal`). Free text can only raise `REVIEW`, never grant `ALLOW`, so rewording a request can't get it through.
- **Protected principals are operator configuration.** They come from code, the environment or the command line, never from the action being judged. An empty `GUARD_PROTECTED_PRINCIPALS` keeps the default rather than switching the rule off.
- **The scanner never stores a raw secret** on a finding.
- **Scope.** These are guard rails for well-behaved automation and agents, not a sandbox. Use OS isolation for code you don't trust.

## Tests

```
make test      # or: python3 -m unittest discover -s tests -t . -b
```

Running `guard-scan` on this repository reports findings: those are the scanner's own deliberate test fixtures and documentation examples, all fake. The provider-shaped fixture tokens (Stripe, GitLab, npm, private-key headers and similar) are built from concatenated parts so that provider-specific scanners and push protection don't match them. gitleaks reports no leaks on this tree. Generic password-style fixtures are left as plain literals because they are what the tests exercise.

## License

Apache-2.0. See [LICENSE](LICENSE).
