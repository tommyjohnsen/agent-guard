# agent-guard: secret scanner, filesystem permission verifier, action policy gate.
# Stdlib Python only; no venv, no network, no root required.

PYTHON ?= python3

.PHONY: test test-scanner test-permcheck test-gate scan clean

test:
	$(PYTHON) -m unittest discover -s tests -t . -b

test-scanner:
	$(PYTHON) -m unittest discover -s tests -t . -b -p 'test_scanner.py'

test-permcheck:
	$(PYTHON) -m unittest discover -s tests -t . -b -p 'test_permcheck.py'

test-gate:
	$(PYTHON) -m unittest discover -s tests -t . -b -p 'test_gate.py'

# Scan this folder with the scanner's own rules. Fixtures are marked guard:allow.
scan:
	$(PYTHON) -m guardlib.scanner .

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
