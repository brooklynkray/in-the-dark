"""
Tests for results.py - parse_nmap_xml(), the pure parser turning
Nmap's -oX output into ScanResult/HostResult/PortResult.

These are fixture-based: static XML strings representing realistic,
and deliberately malformed or unusual, Nmap output. No live Nmap or
network access is used anywhere in this file.
"""

import pytest

import results


# ---------------------------------------------------------------------------
# A normal, multi-port scan
# ---------------------------------------------------------------------------

NORMAL_SCAN_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parses_a_normal_multi_port_scan():
    scan_result = results.parse_nmap_xml(NORMAL_SCAN_XML)

    assert scan_result.host.status == "up"
    assert scan_result.host.ports == (
        results.PortResult(22, "tcp", "open", "ssh", "OpenSSH", "8.2"),
        results.PortResult(80, "tcp", "open", "http", "Apache", None),
        results.PortResult(443, "tcp", "open", "https", "nginx", None),
    )


# ---------------------------------------------------------------------------
# Host down / no ports found
# ---------------------------------------------------------------------------

HOST_DOWN_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="down"/>
  </host>
</nmaprun>
"""


def test_parses_a_down_host_with_no_ports():
    scan_result = results.parse_nmap_xml(HOST_DOWN_XML)
    assert scan_result.host.status == "down"
    assert scan_result.host.ports == ()


CLOSED_AND_FILTERED_PORTS_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="filtered"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parses_ports_with_no_service_detected():
    scan_result = results.parse_nmap_xml(CLOSED_AND_FILTERED_PORTS_XML)
    assert scan_result.host.ports == (
        results.PortResult(22, "tcp", "closed", None, None, None),
        results.PortResult(8080, "tcp", "filtered", None, None, None),
    )


# ---------------------------------------------------------------------------
# Malformed / incomplete / unexpected XML - must return None, never raise
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("xml_text", [
    "",
    "   ",
    "not xml at all",
    '<nmaprun><host><status state="up"',   # truncated, unclosed tags
    "<nmaprun></nmaprun>",                  # well-formed, but no <host>
    "<nmaprun><host></host></nmaprun>",     # host with no <status>
    '<nmaprun><host><status/></host></nmaprun>',  # status with no state attr
])
def test_malformed_or_incomplete_xml_returns_none(xml_text):
    assert results.parse_nmap_xml(xml_text) is None


def test_none_input_returns_none():
    assert results.parse_nmap_xml(None) is None


PORT_WITH_INVALID_PORTID_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="not-a-number">
        <state state="open"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_a_single_malformed_port_is_skipped_not_fatal():
    scan_result = results.parse_nmap_xml(PORT_WITH_INVALID_PORTID_XML)
    # The malformed port is silently dropped; the rest of the scan
    # still parses rather than the whole result being discarded.
    assert scan_result.host.ports == (
        results.PortResult(22, "tcp", "open", None, None, None),
    )


PORT_WITH_NO_STATE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="22">
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_a_port_missing_state_is_skipped_not_fatal():
    scan_result = results.parse_nmap_xml(PORT_WITH_NO_STATE_XML)
    assert scan_result.host.ports == (
        results.PortResult(80, "tcp", "open", None, None, None),
    )


# ---------------------------------------------------------------------------
# Unusual (but legal) content in target-controlled fields - the parser must
# treat this as inert data: extracted faithfully, never interpreted.
# ---------------------------------------------------------------------------

SPECIAL_CHARACTERS_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http" product="A &amp; B &lt;Co&gt; &quot;Ltd&quot;" version="1.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_xml_entity_escaped_characters_round_trip_correctly():
    # Product strings can legitimately contain characters that XML
    # requires escaping (&, <, >, "). The parser must decode these
    # back to the real characters, not leave them escaped, and treat
    # the result as inert data - never interpret or execute it.
    scan_result = results.parse_nmap_xml(SPECIAL_CHARACTERS_XML)
    port = scan_result.host.ports[0]
    assert port.product == 'A & B <Co> "Ltd"'


# Written as an escape sequence, deliberately, rather than a raw
# character - embedding a real bidi-control character directly in
# this source file would make the file itself confusing to read in
# an editor or diff, which is exactly the failure mode this test
# exists to check the parser doesn't paper over.
RTL_OVERRIDE = "\u202e"

UNICODE_OVERRIDE_XML = (
    '<?xml version="1.0"?>\n'
    "<nmaprun>\n"
    "  <host>\n"
    '    <status state="up"/>\n'
    "    <ports>\n"
    '      <port protocol="tcp" portid="8080">\n'
    '        <state state="open"/>\n'
    f'        <service name="http" product="innocent{RTL_OVERRIDE}exe.jpg"/>\n'
    "      </port>\n"
    "    </ports>\n"
    "  </host>\n"
    "</nmaprun>\n"
)


def test_unicode_formatting_characters_are_preserved_as_inert_data():
    # U+202E (right-to-left override) is a legal Unicode/XML character
    # sometimes used to visually disguise text. This module's job is
    # only to extract data faithfully, not to interpret or sanitise
    # it - what the display layer does with potentially misleading
    # Unicode is a separate, out-of-scope concern for this module.
    scan_result = results.parse_nmap_xml(UNICODE_OVERRIDE_XML)
    port = scan_result.host.ports[0]
    assert port.product == f"innocent{RTL_OVERRIDE}exe.jpg"
