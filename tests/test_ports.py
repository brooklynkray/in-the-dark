"""
Tests for ports.py - parse_custom_ports(), the validator for
user-supplied Nmap -p specifications.

These are the first tests in this project that need to prove a
free-form, user-typed string is rejected outright when malformed or
hostile, mirroring tests/test_target.py's approach for target
strings.
"""

import pytest

import ports


# ---------------------------------------------------------------------------
# Valid input is accepted and returned normalized
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "80",
    "80,443",
    "1-1024",
    "22,80,443",
    "1-1024,3389",
    "65535",
    "1",
])
def test_valid_port_specs_are_accepted(text):
    assert ports.parse_custom_ports(text) == text


def test_leading_and_trailing_whitespace_is_stripped():
    assert ports.parse_custom_ports("  80,443  ") == "80,443"


# ---------------------------------------------------------------------------
# Malformed syntax is rejected
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "",
    "   ",
    "abc",
    "80,",
    ",80",
    "80,,443",
    "1-1024-2048",
    "1--1024",
    "80-",
    "-1024",
    "80 443",
    "80, 443",
    "80 ,443",
])
def test_malformed_syntax_is_rejected(text):
    assert ports.parse_custom_ports(text) is None


# ---------------------------------------------------------------------------
# Out-of-range / backwards / invalid numeric values are rejected
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "0",
    "0-100",
    "65536",
    "70000",
    "443-80",
    "100-99",
])
def test_invalid_port_numbers_are_rejected(text):
    assert ports.parse_custom_ports(text) is None


# ---------------------------------------------------------------------------
# Duplicates are rejected
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "80,80",
    "80,443,80",
    "1-1024,1-1024",
])
def test_exact_duplicate_entries_are_rejected(text):
    assert ports.parse_custom_ports(text) is None


# ---------------------------------------------------------------------------
# Protocol prefixes are rejected - this is what keeps UDP out of scope
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "T:80",
    "U:53",
    "U:53,80",
    "T:80,U:53",
    "S:80",
])
def test_protocol_prefixes_are_rejected(text):
    assert ports.parse_custom_ports(text) is None


# ---------------------------------------------------------------------------
# Injection-shaped input is rejected outright
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("hostile_input", [
    "80;rm -rf /",
    "80 && whoami",
    "$(whoami)",
    "`whoami`",
    "--script=malicious",
    "80\nrm -rf /",
    "80 -oN pwned.txt",
])
def test_injection_shaped_input_is_rejected(hostile_input):
    assert ports.parse_custom_ports(hostile_input) is None
