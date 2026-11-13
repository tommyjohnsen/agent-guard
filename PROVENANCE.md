# Provenance

Generated from `.provenance/ledger.jsonl`; do not edit by hand. The ledger is the record of truth; per-file PROVENANCE headers mirror it. History without an established author remains `unknown (pre-provenance)`.

Each ledger line has `path`, `blob`, `event`, `by`, `date`, and either `commit` (written) or `verdict`, `head`, `record` (reviewed). `blob` is the Git blob SHA-1 after removing the complete PROVENANCE header, including enclosing Markdown comment lines. JSON and LICENSE are ledger-only.

A source commit cannot contain its own SHA. The implementation commit initially uses a resolvable Git message revision; a following provenance-only commit records that implementation SHA in its headers and ledger. No substantive code changes occur in that metadata commit.

Current exact-commit reviews for this change: **pending** from both claude-code and grok-build. Historical review records below remain history, not approval of the current HEAD. The mandatory Tommy rule requires both seats to APPROVE the current exact SHA before merging, tagging or releasing; any subsequent commit voids that approval. No self-review has been recorded.

Files tracked: 23. Current written records: 23/23.

| path | written-by (current content) | current exact-SHA review |
| --- | --- | --- |
| `.github/workflows/test.yml` | codex/gpt-6 | pending |
| `.gitignore` | unknown (pre-provenance) | pending |
| `LICENSE` | unknown (pre-provenance) | pending |
| `Makefile` | codex/gpt-6 | pending |
| `README.md` | codex/gpt-6 | pending |
| `docs/source-isolation.md` | codex/gpt-6 | pending |
| `docs/validation.md` | codex/gpt-6 | pending |
| `examples/capstone.policy.json` | codex/gpt-6 | pending |
| `examples/make_synthetic_policy.py` | codex/gpt-6 | pending |
| `guardlib/__init__.py` | unknown (pre-provenance) | pending |
| `guardlib/_sandbox.py` | codex/gpt-6 | pending |
| `guardlib/gate.py` | unknown (pre-provenance) | pending |
| `guardlib/permcheck.py` | codex/gpt-5.6-sol | pending |
| `guardlib/relay.py` | codex/gpt-6 | pending |
| `guardlib/runner.py` | codex/gpt-6 | pending |
| `guardlib/scanner.py` | codex/gpt-5.6-sol | pending |
| `pyproject.toml` | codex/gpt-6 | pending |
| `tests/__init__.py` | unknown (pre-provenance) | pending |
| `tests/test_gate.py` | unknown (pre-provenance) | pending |
| `tests/test_permcheck.py` | codex/gpt-5.6-sol | pending |
| `tests/test_relay.py` | codex/gpt-6 | pending |
| `tests/test_runner.py` | codex/gpt-6 | pending |
| `tests/test_scanner.py` | codex/gpt-5.6-sol | pending |
