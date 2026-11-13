# PROVENANCE (mirror of .provenance/ledger.jsonl; ledger wins)
# written-by: codex/gpt-6 | 2026-11-13 | :/isolate-capstone-sources-v1
# reviews: pending current exact-commit claude-code and grok-build approval
# END PROVENANCE
"""Create a NEW synthetic demo directory; never inspect or alter real sources."""

import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", help="new absolute directory, e.g. /tmp/capstone-demo")
    args = parser.parse_args()
    root = Path(args.directory)
    if not root.is_absolute():
        parser.error("use an absolute path")
    root.mkdir(mode=0o700)  # Existing directories are deliberately refused.
    for name in ("public", "notes", "licensed", "unclassified", "out", "cache", "tmp"):
        (root / name).mkdir(mode=0o700)
    (root / "public/cleared.txt").write_bytes(b"Synthetic source explicitly cleared for AI.\n")
    (root / "notes/interpretation.txt").write_bytes(b"Synthetic personal interpretation cleared for AI.\n")
    (root / "licensed/forbidden.txt").write_bytes(b"FAKE licensed fixture; no licensed material.\n")
    (root / "unclassified/new.txt").write_bytes(b"FAKE new source without clearance.\n")
    inputs = []
    for name, filename, clearance in (("public", "cleared.txt", "PUBLIC/ALT"),
                                      ("notes", "interpretation.txt", "NOTES")):
        inputs.append({"id": name, "path": str(root / name), "files": [{
            "path": filename, "class": clearance,
            "sha256": hashlib.sha256((root / name / filename).read_bytes()).hexdigest()}]})
    policy = {"version": 1, "runtime": [{"source": "/usr", "target": "/usr"}],
              "input_roots": inputs,
              "writable": {name: str(root / name) for name in ("out", "cache", "tmp")},
              "network": {"mode": "none"}}
    path = root / "policy.json"
    path.write_text(json.dumps(policy, indent=2) + "\n")
    path.chmod(0o600)
    print(path)


if __name__ == "__main__":
    main()
