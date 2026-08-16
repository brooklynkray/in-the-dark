"""
Characterisation tests for target.py's existing validation and
classification behaviour, with particular attention to
injection-shaped input - these values must be rejected outright, not
parsed, split, or passed through to a command.
"""

import pytest

import target


def test_valid_ipv4_is_identified():
    assert target.identify_target("10.10.10.5") == "IPv4"


def test_valid_ipv6_is_identified():
    assert target.identify_target("::1") == "IPv6"


def test_valid_hostname_is_identified():
    assert target.identify_target("example.com") == "hostname"


def test_out_of_range_dotted_quad_is_invalid():
    # Looks like an IPv4 address but each octet is out of range - must
    # not silently fall through and be accepted as a hostname.
    assert target.identify_target("999.999.999.999") == "invalid"


@pytest.mark.parametrize("hostile_input", [
    "10.10.10.5; rm -rf /",
    "10.10.10.5 && whoami",
    "$(whoami)",
    "`whoami`",
    "example.com; ls",
    "-oN pwned.txt",
    "--script=malicious",
    "example.com/../../etc/passwd",
    "example.com\nrm -rf /",
])
def test_injection_shaped_input_is_rejected(hostile_input):
    assert target.identify_target(hostile_input) == "invalid"
    assert target.create_target(hostile_input) is None
