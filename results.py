#!/usr/bin/env python3
"""
results.py
----------

Parsing Nmap's XML scan output into a small, structured Python data
model.

This module owns the one place Nmap's -oX output is turned into
something a program can address directly (port.state, port.service,
...) instead of scraping Nmap's human-readable text, which carries no
stability guarantees between Nmap versions - column layout, wording,
and edge-case formatting can all change release to release. Nmap's
XML format, by contrast, is documented and versioned specifically for
other programs to consume - it is the intended integration point, not
a workaround.

Security note: the XML text handed to parse_nmap_xml() is produced by
a locally-run, trusted copy of Nmap - it is not attacker-supplied XML
in the sense that matters for XXE (XML External Entity) attacks,
which require the *document itself* to be crafted by an adversary.
xml.etree.ElementTree is used here rather than a hardened
network-facing XML library because that specific threat does not
apply to this data source, and modern CPython's ElementTree does not
resolve external entities the way historically-vulnerable parser
configurations did.

What genuinely IS attacker-influenced is the *content* inside
individual fields - service banners, product/version strings - since
those ultimately reflect the remote target's own responses. Two
things are worth stating precisely about that:

- Raw ASCII control characters (e.g. terminal escape sequences) are
  not legal within well-formed XML 1.0 documents, even as numeric
  character references, which structurally limits (though does not
  eliminate) how much of that category of content can even arrive
  here intact.
- Legal-but-unusual content (e.g. Unicode formatting/bidi-override
  characters) can absolutely arrive here, and this module treats it
  as inert data - it is extracted faithfully, never interpreted or
  sanitised. Deciding how to *display* such content safely is a
  separate, explicitly out-of-scope concern for the presentation
  layer, not this one.

Nothing in this module touches subprocess, the filesystem, or argv -
it only turns XML text that is already in memory into plain data.
Malformed, truncated, or unexpected XML never raises here - it
produces None, so a parsing failure degrades to "structured results
unavailable" rather than crashing the application.
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass(frozen=True)
class PortResult:
    port: int
    protocol: str
    state: str
    service: str | None
    product: str | None
    version: str | None


@dataclass(frozen=True)
class HostResult:
    status: str
    ports: tuple[PortResult, ...]


@dataclass(frozen=True)
class ScanResult:
    host: HostResult


def parse_nmap_xml(xml_text):
    """
    Parse Nmap's -oX output into a ScanResult.

    Returns None if `xml_text` is empty, malformed, or doesn't
    contain the structure this module expects (no <host> element, no
    <status>) - never raises on untrusted-shaped input. A single
    malformed <port> is skipped rather than discarding the whole
    result, since one bad entry shouldn't hide everything else the
    scan found.
    """

    if not xml_text or not xml_text.strip():
        return None

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    host_element = root.find("host")
    if host_element is None:
        return None

    status_element = host_element.find("status")
    if status_element is None:
        return None

    status = status_element.get("state")
    if status is None:
        return None

    ports = []
    ports_element = host_element.find("ports")
    if ports_element is not None:
        for port_element in ports_element.findall("port"):
            port_result = _parse_port(port_element)
            if port_result is not None:
                ports.append(port_result)

    return ScanResult(host=HostResult(status=status, ports=tuple(ports)))


def _parse_port(port_element):
    """Parse a single <port> element, or return None if malformed."""

    protocol = port_element.get("protocol")
    portid = port_element.get("portid")

    if protocol is None or portid is None:
        return None

    try:
        port = int(portid)
    except ValueError:
        return None

    state_element = port_element.find("state")
    if state_element is None:
        return None

    state = state_element.get("state")
    if state is None:
        return None

    service_element = port_element.find("service")
    if service_element is not None:
        service = service_element.get("name")
        product = service_element.get("product")
        version = service_element.get("version")
    else:
        service = product = version = None

    return PortResult(
        port=port,
        protocol=protocol,
        state=state,
        service=service,
        product=product,
        version=version,
    )
