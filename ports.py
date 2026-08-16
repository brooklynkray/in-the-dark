#!/usr/bin/env python3
"""
ports.py
--------

Validation for user-supplied Nmap -p port specifications.

This module owns the one place a raw, free-form port specification
string is checked before it can ever become part of a ScanConfig. It
mirrors target.py's role for target strings: a focused,
independently-testable validator that returns either a normalized,
known-good string or None - never a partially-fixed-up guess at what
the user meant.

The accepted grammar is deliberately narrower than everything Nmap's
own -p flag supports:

- single ports (80) and closed ranges (1-1024), comma-separated
- no open-ended ranges (-1024, 1024-)
- no protocol prefixes (T:80, U:53, ...) - accepting these would let
  UDP scanning in through the back door, which this project has
  repeatedly and deliberately kept out of scope
- no whitespace, no duplicate entries, no range-overlap detection
  (Nmap already de-duplicates ports internally regardless)

Nothing in this module touches subprocess, argv, or ScanConfig - it
only answers "is this a well-formed port specification".
"""

import re

MIN_PORT = 1
MAX_PORT = 65535

_PORT_TOKEN = r"\d{1,5}(?:-\d{1,5})?"
_PORT_SPEC_PATTERN = re.compile(rf"^{_PORT_TOKEN}(?:,{_PORT_TOKEN})*$")


def parse_custom_ports(text):
    """
    Validate and normalize a user-supplied -p port specification.

    Returns the normalized string on success, or None if `text` is
    not a well-formed specification under this module's deliberately
    narrowed grammar (see module docstring). A leading/trailing
    protocol prefix such as "T:80" or "U:53" is rejected here, not
    silently accepted - this is the one thing that must never slip
    through, since it's how UDP scanning would otherwise sneak in.
    """

    text = text.strip()

    if not text or not _PORT_SPEC_PATTERN.fullmatch(text):
        return None

    tokens = text.split(",")

    if len(tokens) != len(set(tokens)):
        return None  # exact duplicate entries

    for token in tokens:
        if "-" in token:
            low_text, high_text = token.split("-")
            low, high = int(low_text), int(high_text)
            if not (MIN_PORT <= low <= high <= MAX_PORT):
                return None
        else:
            port = int(token)
            if not (MIN_PORT <= port <= MAX_PORT):
                return None

    return text
