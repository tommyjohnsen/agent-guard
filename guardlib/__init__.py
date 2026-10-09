"""guard: secret scanning, filesystem permission checks, and an action policy gate.

Stdlib only. The scanner and gate are pure; permcheck shells out to read-only
``getfacl`` when it is available and degrades gracefully when it is not.
"""

__all__ = ["scanner", "permcheck", "gate"]
__version__ = "0.1.0"
