# PROVENANCE (mirror of .provenance/ledger.jsonl; ledger wins)
# written-by: unknown (pre-provenance) | 2026-10-09 | f032f17ae5ef38af48d96e0a5c10e4bce725fbba
# modified-by: codex/gpt-6 | 2026-11-13 | fdeaacfb9f10fa420f943572f343014a8be6129d
# reviews: pending current exact-commit claude-code and grok-build approval
# END PROVENANCE
# agent-guard: secret scanner, filesystem permission verifier, action policy gate.
# Stdlib Python only; no venv, no network, no root required.

PYTHON ?= python3

.PHONY: test test-scanner test-permcheck test-gate test-isolation scan clean

test:
	$(PYTHON) -m unittest discover -s tests -t . -b

test-scanner:
	$(PYTHON) -m unittest discover -s tests -t . -b -p 'test_scanner.py'

test-permcheck:
	$(PYTHON) -m unittest discover -s tests -t . -b -p 'test_permcheck.py'

test-gate:
	$(PYTHON) -m unittest discover -s tests -t . -b -p 'test_gate.py'

test-isolation:
	GUARD_REQUIRE_ISOLATION=1 $(PYTHON) -m unittest tests.test_runner tests.test_relay -v

# Scan this folder with the scanner's own rules. Fixtures are marked guard:allow.
scan:
	$(PYTHON) -m guardlib.scanner .

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
