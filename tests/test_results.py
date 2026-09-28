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


# ---------------------------------------------------------------------------
# Richer fields for the next stage (service enumeration guidance).
#
# This fixture is HAND-WRITTEN to follow the structure of Nmap's -oX
# format (element and attribute names per Nmap's nmap.dtd) - it was
# not captured from a real scan. Swap in a real capture from a lab box
# when one is available; the assertions should not need to change.
# ---------------------------------------------------------------------------

DETAILED_SCAN_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -O -oX - 10.10.10.5" version="7.95">
  <host starttime="1" endtime="2">
    <status state="up" reason="conn-refused" reason_ttl="0"/>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <address addr="02:42:AC:11:00:02" addrtype="mac" vendor="Unknown"/>
    <hostnames>
      <hostname name="lab.thm" type="user"/>
      <hostname name="ip-10-10-10-5.eu-west-1.compute.internal" type="PTR"/>
      <hostname name="lab.thm" type="PTR"/>
    </hostnames>
    <ports>
      <extraports state="closed" count="996">
        <extrareasons reason="conn-refused" count="996"/>
      </extraports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5"
                 extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux"
                 method="probed" conf="10">
          <cpe>cpe:/a:openbsd:openssh:8.2p1</cpe>
          <cpe>cpe:/o:linux:linux_kernel</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http" product="nginx" version="1.18.0" tunnel="ssl"
                 method="probed" conf="10">
          <cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http-proxy" method="table" conf="3"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="abyss" method="table" conf="banana"/>
      </port>
    </ports>
    <os>
      <portused state="open" proto="tcp" portid="22"/>
      <osmatch name="Linux 4.15 - 5.19" accuracy="96" line="1">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" accuracy="96"/>
      </osmatch>
      <osmatch name="Linux 5.4" accuracy="93" line="2"/>
      <osmatch accuracy="90" line="3"/>
    </os>
  </host>
  <runstats>
    <finished time="2" timestr="x" elapsed="12.3" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
"""


def test_detailed_scan_keeps_host_level_detail():
    scan_result = results.parse_nmap_xml(DETAILED_SCAN_XML)
    host = scan_result.host

    assert host.status == "up"
    assert host.status_reason == "conn-refused"
    assert host.addresses == (
        results.Address("10.10.10.5", "ipv4"),
        results.Address("02:42:AC:11:00:02", "mac"),
    )
    # Duplicate names (user-supplied and PTR) are listed once.
    assert host.hostnames == (
        "lab.thm",
        "ip-10-10-10-5.eu-west-1.compute.internal",
    )
    assert host.extra_ports == (results.ExtraPorts("closed", 996),)


def test_detailed_scan_keeps_service_detail():
    ports = results.parse_nmap_xml(DETAILED_SCAN_XML).host.ports
    ssh, https, proxy, abyss = ports

    assert ssh.product == "OpenSSH"
    assert ssh.version == "8.2p1 Ubuntu 4ubuntu0.5"
    assert ssh.extrainfo == "Ubuntu Linux; protocol 2.0"
    assert ssh.method == "probed"
    assert ssh.confidence == 10
    assert ssh.reason == "syn-ack"
    assert ssh.cpes == (
        "cpe:/a:openbsd:openssh:8.2p1",
        "cpe:/o:linux:linux_kernel",
    )

    assert https.service == "http"
    assert https.tunnel == "ssl"

    assert proxy.method == "table"
    assert proxy.confidence == 3
    assert proxy.cpes == ()

    # A non-numeric conf degrades to None rather than dropping the port.
    assert abyss.port == 9999
    assert abyss.confidence is None


def test_detailed_scan_keeps_os_matches_and_skips_nameless_ones():
    host = results.parse_nmap_xml(DETAILED_SCAN_XML).host
    assert host.os_matches == (
        results.OsMatch("Linux 4.15 - 5.19", 96),
        results.OsMatch("Linux 5.4", 93),
    )


def test_detailed_scan_keeps_run_level_status():
    scan_result = results.parse_nmap_xml(DETAILED_SCAN_XML)
    assert scan_result.exit_status == "success"
    assert scan_result.error_message is None
    assert scan_result.hosts_up == 1
    assert scan_result.hosts_down == 0
    assert scan_result.host_seems_down is False


def test_original_fields_still_work_without_the_new_ones():
    # Positional construction with only the original six fields must
    # keep working - every new field has a default.
    port = results.PortResult(22, "tcp", "open", "ssh", "OpenSSH", "8.2")
    assert port.extrainfo is None
    assert port.cpes == ()


# ---------------------------------------------------------------------------
# Host seems down - with and without a <host> element
# ---------------------------------------------------------------------------

# Also hand-written: the shape we expect when Nmap gets no answer to
# host discovery and (at normal verbosity) writes no <host> at all.
NO_HOST_ELEMENT_DOWN_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -oX - 10.10.10.5">
  <runstats>
    <finished time="2" elapsed="3.1" exit="success"
              summary="Nmap done; 1 IP address (0 hosts up) scanned"/>
    <hosts up="0" down="1" total="1"/>
  </runstats>
</nmaprun>
"""


def test_down_host_without_host_element_is_recognised_not_none():
    scan_result = results.parse_nmap_xml(NO_HOST_ELEMENT_DOWN_XML)
    assert scan_result is not None
    assert scan_result.host is None
    assert scan_result.hosts_down == 1
    assert scan_result.hosts_up == 0
    assert scan_result.host_seems_down is True


def test_down_host_with_host_element_is_recognised():
    scan_result = results.parse_nmap_xml(HOST_DOWN_XML)
    assert scan_result.host_seems_down is True


def test_up_host_is_not_reported_down():
    scan_result = results.parse_nmap_xml(NORMAL_SCAN_XML)
    assert scan_result.host_seems_down is False


RUN_ERROR_XML = """<?xml version="1.0"?>
<nmaprun>
  <runstats>
    <finished time="1" exit="error" errormsg="Something went wrong"/>
    <hosts up="0" down="0" total="0"/>
  </runstats>
</nmaprun>
"""


def test_nmap_run_error_is_kept_and_not_mistaken_for_host_down():
    scan_result = results.parse_nmap_xml(RUN_ERROR_XML)
    assert scan_result.host is None
    assert scan_result.exit_status == "error"
    assert scan_result.error_message == "Something went wrong"
    assert scan_result.host_seems_down is False


@pytest.mark.parametrize("xml_text", [
    # runstats present but with nothing usable in it
    "<nmaprun><runstats></runstats></nmaprun>",
    '<nmaprun><runstats><hosts up="x" down="y"/></runstats></nmaprun>',
])
def test_runstats_without_usable_counts_returns_none(xml_text):
    assert results.parse_nmap_xml(xml_text) is None
