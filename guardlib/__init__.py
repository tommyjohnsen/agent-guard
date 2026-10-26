# PROVENANCE (mirror of .provenance/ledger.jsonl; ledger wins)
# written-by: unknown (pre-provenance) | 2026-10-09 | f032f17
# modified-by: codex/gpt-5.6-sol | 2026-10-26 | 1aaa682 | provenance block added
# END PROVENANCE
"""guard: secret scanning, filesystem permission checks, and an action policy gate.

Stdlib only. The scanner and gate are pure; permcheck shells out to read-only
``getfacl`` when it is available and degrades gracefully when it is not.
"""

__all__ = ["scanner", "permcheck", "gate"]
__version__ = "0.1.0"
