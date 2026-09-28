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

What is kept, and why: the data model deliberately carries what the
next stage (service-specific enumeration guidance) needs to reason
about a finding, not just what fits on one display line:

- per port: Nmap's service guess plus how it was reached (`method`
  "probed" = a real -sV probe matched, "table" = just looked up from
  the port number) and its confidence, extra info, SSL/TLS tunnel,
  and CPE identifiers (standard product names, useful for matching
  against vulnerability data later)
- per host: addresses, hostnames, OS guesses, and the "Not shown: N
  closed/filtered ports" summary Nmap uses instead of listing every
  uninteresting port
- per run: Nmap's own exit status and host up/down counts. A down
  host may have no <host> element at all (as far as we know, Nmap
  only writes one for a down host at higher verbosity - confirm
  against real output), so these counts are what let a "host seems
  down" result be told apart from "parsing failed".

Every new field has a default, so code that only knows the original
fields keeps working unchanged.
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
    extrainfo: str | None = None
    tunnel: str | None = None
    method: str | None = None
    confidence: int | None = None
    cpes: tuple[str, ...] = ()
    reason: str | None = None


@dataclass(frozen=True)
class Address:
    addr: str
    addrtype: str


@dataclass(frozen=True)
class OsMatch:
    name: str
    accuracy: int | None


@dataclass(frozen=True)
class ExtraPorts:
    """Nmap's "Not shown: <count> <state> ports" summary line."""

    state: str
    count: int


@dataclass(frozen=True)
class HostResult:
    status: str
    ports: tuple[PortResult, ...]
    status_reason: str | None = None
    addresses: tuple[Address, ...] = ()
    hostnames: tuple[str, ...] = ()
    os_matches: tuple[OsMatch, ...] = ()
    extra_ports: tuple[ExtraPorts, ...] = ()


@dataclass(frozen=True)
class ScanResult:
    """
    The structured outcome of one Nmap run.

    `host` is None when Nmap produced no <host> element - in practice,
    because the host did not answer host discovery. The run-level
    fields (from <runstats>) are what make that case recognisable
    rather than indistinguishable from "parsing failed".
    """

    host: HostResult | None
    hosts_up: int | None = None
    hosts_down: int | None = None
    exit_status: str | None = None
    error_message: str | None = None

    @property
    def host_seems_down(self):
        """True if Nmap concluded the target was not up."""

        if self.host is not None:
            return self.host.status == "down"

        return bool(self.hosts_down) and not self.hosts_up


def parse_nmap_xml(xml_text):
    """
    Parse Nmap's -oX output into a ScanResult.

    Returns None if `xml_text` is empty, malformed, or doesn't
    contain the structure this module expects - never raises on
    untrusted-shaped input. "The structure this module expects" means
    either a <host> element with a <status>, or (when Nmap omitted the
    host because it seemed down) a <runstats> element carrying host
    counts. A single malformed <port>, address or OS match is skipped
    rather than discarding the whole result, since one bad entry
    shouldn't hide everything else the scan found.
    """

    if not xml_text or not xml_text.strip():
        return None

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    hosts_up, hosts_down, exit_status, error_message = _parse_runstats(root)

    host_element = root.find("host")
    if host_element is None:
        if hosts_up is None and hosts_down is None:
            return None  # nothing recognisable at all

        return ScanResult(
            host=None,
            hosts_up=hosts_up,
            hosts_down=hosts_down,
            exit_status=exit_status,
            error_message=error_message,
        )

    host = _parse_host(host_element)
    if host is None:
        return None

    return ScanResult(
        host=host,
        hosts_up=hosts_up,
        hosts_down=hosts_down,
        exit_status=exit_status,
        error_message=error_message,
    )


def _int_or_none(text):
    """Convert an attribute value to int, or None if absent/invalid."""

    if text is None:
        return None

    try:
        return int(text)
    except ValueError:
        return None


def _parse_runstats(root):
    """
    Return (hosts_up, hosts_down, exit_status, error_message) from
    <runstats>, with None for anything missing or malformed.
    """

    runstats = root.find("runstats")
    if runstats is None:
        return None, None, None, None

    hosts_up = hosts_down = exit_status = error_message = None

    hosts_element = runstats.find("hosts")
    if hosts_element is not None:
        hosts_up = _int_or_none(hosts_element.get("up"))
        hosts_down = _int_or_none(hosts_element.get("down"))

    finished_element = runstats.find("finished")
    if finished_element is not None:
        exit_status = finished_element.get("exit")
        error_message = finished_element.get("errormsg")

    return hosts_up, hosts_down, exit_status, error_message


def _parse_host(host_element):
    """Parse a <host> element, or return None if it has no usable status."""

    status_element = host_element.find("status")
    if status_element is None:
        return None

    status = status_element.get("state")
    if status is None:
        return None

    ports = []
    extra_ports = []
    ports_element = host_element.find("ports")
    if ports_element is not None:
        for port_element in ports_element.findall("port"):
            port_result = _parse_port(port_element)
            if port_result is not None:
                ports.append(port_result)

        for extra_element in ports_element.findall("extraports"):
            state = extra_element.get("state")
            count = _int_or_none(extra_element.get("count"))
            if state is not None and count is not None:
                extra_ports.append(ExtraPorts(state=state, count=count))

    addresses = []
    for address_element in host_element.findall("address"):
        addr = address_element.get("addr")
        addrtype = address_element.get("addrtype")
        if addr is not None and addrtype is not None:
            addresses.append(Address(addr=addr, addrtype=addrtype))

    hostnames = []
    hostnames_element = host_element.find("hostnames")
    if hostnames_element is not None:
        for hostname_element in hostnames_element.findall("hostname"):
            name = hostname_element.get("name")
            if name is not None and name not in hostnames:
                hostnames.append(name)

    os_matches = []
    os_element = host_element.find("os")
    if os_element is not None:
        for match_element in os_element.findall("osmatch"):
            name = match_element.get("name")
            if name is not None:
                os_matches.append(OsMatch(
                    name=name,
                    accuracy=_int_or_none(match_element.get("accuracy")),
                ))

    return HostResult(
        status=status,
        ports=tuple(ports),
        status_reason=status_element.get("reason"),
        addresses=tuple(addresses),
        hostnames=tuple(hostnames),
        os_matches=tuple(os_matches),
        extra_ports=tuple(extra_ports),
    )


def _parse_port(port_element):
    """Parse a single <port> element, or return None if malformed."""

    protocol = port_element.get("protocol")
    portid = port_element.get("portid")

    if protocol is None or portid is None:
        return None

    port = _int_or_none(portid)
    if port is None:
        return None

    state_element = port_element.find("state")
    if state_element is None:
        return None

    state = state_element.get("state")
    if state is None:
        return None

    service = product = version = extrainfo = tunnel = method = None
    confidence = None
    cpes = ()

    service_element = port_element.find("service")
    if service_element is not None:
        service = service_element.get("name")
        product = service_element.get("product")
        version = service_element.get("version")
        extrainfo = service_element.get("extrainfo")
        tunnel = service_element.get("tunnel")
        method = service_element.get("method")
        confidence = _int_or_none(service_element.get("conf"))
        cpes = tuple(
            cpe_element.text.strip()
            for cpe_element in service_element.findall("cpe")
            if cpe_element.text and cpe_element.text.strip()
        )

    return PortResult(
        port=port,
        protocol=protocol,
        state=state,
        service=service,
        product=product,
        version=version,
        extrainfo=extrainfo,
        tunnel=tunnel,
        method=method,
        confidence=confidence,
        cpes=cpes,
        reason=state_element.get("reason"),
    )
