# Provenance

Generated from `.provenance/ledger.jsonl` by the operator tool; do not edit by hand. The ledger is the record of truth; per-file `PROVENANCE` headers mirror it, and the ledger wins on any disagreement.

Each ledger line is one JSON object with `path`, `blob`, `event` (`written` or `reviewed`), `by` (seat/model, or `unknown (pre-provenance)` for history whose author is not recorded), `date`, and either `commit` (written) or `verdict`, `head` and `record` (reviewed). Verdicts are `APPROVE`, `APPROVE_WITH_NITS` or `REJECT`.

`blob` is the git blob SHA-1 of the file after removing its PROVENANCE header block: the lines from the `PROVENANCE` line through the `END PROVENANCE` line inclusive, plus a directly enclosing `<!--` / `-->` line pair. A review applies only while the file's current `blob` equals the reviewed one; any content change makes it stale. A release needs current reviews from claude-code and grok-build; an author never reviews its own work.

Files tracked: 14 (excluding this summary and `.provenance/`). Inline headers: 13. Ledger-only: 1. Written entries current: 14/14. Current reviews: claude-code 14, grok-build 14. Current REJECTs: 0.

| path | header | written-by (current content) | claude-code | grok-build |
|---|---|---|---|---|
| `.github/workflows/test.yml` | inline | unknown (pre-provenance) | APPROVE | APPROVE |
| `.gitignore` | inline | unknown (pre-provenance) | APPROVE | APPROVE |
| `LICENSE` | ledger | unknown (pre-provenance) | APPROVE | APPROVE |
| `Makefile` | inline | unknown (pre-provenance) | APPROVE | APPROVE |
| `README.md` | inline | unknown (pre-provenance) | APPROVE | APPROVE |
| `guardlib/__init__.py` | inline | unknown (pre-provenance) | APPROVE | APPROVE |
| `guardlib/gate.py` | inline | unknown (pre-provenance) | APPROVE | APPROVE |
| `guardlib/permcheck.py` | inline | codex/gpt-5.6-sol | APPROVE | APPROVE |
| `guardlib/scanner.py` | inline | codex/gpt-5.6-sol | APPROVE_WITH_NITS | APPROVE_WITH_NITS |
| `pyproject.toml` | inline | unknown (pre-provenance) | APPROVE | APPROVE |
| `tests/__init__.py` | inline | unknown (pre-provenance) | APPROVE | APPROVE |
| `tests/test_gate.py` | inline | unknown (pre-provenance) | APPROVE | APPROVE |
| `tests/test_permcheck.py` | inline | codex/gpt-5.6-sol | APPROVE_WITH_NITS | APPROVE |
| `tests/test_scanner.py` | inline | codex/gpt-5.6-sol | APPROVE_WITH_NITS | APPROVE_WITH_NITS |
