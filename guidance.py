#!/usr/bin/env python3
"""
guidance.py
-----------

Turns a parsed scan result into "where to look next" guidance, one
open port at a time.

This is the module that makes In the Dark more than a friendlier Nmap:
instead of only reporting what is open, it explains, for each open
service, what it is, why it matters, what to check next, and which
established tools do that job. It is aimed at someone who has a scan
result in front of them and is asking "now what?".

Design, and the reasons for it:

- Pure and deterministic. Every producer here takes data and returns a
  Guidance object. Nothing runs a subprocess, prints, touches the
  filesystem, or looks at the local machine. That keeps the judgement
  fully unit-testable without a live target, and keeps the one
  system-dependent step (is a suggested tool installed?) in the
  presentation layer, where it belongs.

- Reacts to evidence Nmap actually has, and never invents certainty.
  The producers branch on real fields of a PortResult - whether the
  service was confirmed or only guessed from the port number
  (`method`), whether a product and version were identified, whether
  the service is TLS-wrapped (`tunnel`), and the port number itself.
  A product/version match becomes a lead to verify with searchsploit,
  never a claim that the target is vulnerable: banners can be faked,
  and Linux distributions backport security fixes, so a version string
  alone proves nothing.

- One explicit producer per service, not a rules engine. Each service
  is a small function chosen by a plain lookup, so the logic for a
  service lives in one readable place. There is no metadata-driven
  loop and no plugin framework - that complexity is not earned here.

- Tool-neutral. Suggested tools are named plainly (whatweb, gobuster,
  ...), not labelled "Kali tools". They are standard security tools
  available on most distributions; they are simply not preinstalled
  everywhere. Whether a given tool is present is decided at display
  time on the machine actually running In the Dark.
"""

from dataclasses import dataclass

from results import PortResult


@dataclass(frozen=True)
class SuggestedCommand:
    """
    One suggested command line and what it is for.

    `tool` is the executable the command starts with (e.g. "gobuster").
    It is kept separate so the presentation layer can check whether
    that tool is installed on this machine, without having to parse it
    back out of `command`.
    """

    command: str
    purpose: str
    tool: str


@dataclass(frozen=True)
class Guidance:
    """
    Structured next-step guidance for one open port. Deliberately not
    a single blob of text: the parts are separate so the presentation
    layer can lay them out consistently, and so tests can assert on
    each part on its own.

    `caution` is the one heads-up that should stand out visually - used
    when the service was only guessed from the port number, so every
    other suggestion here is provisional until it is confirmed.
    """

    what: str
    why: str
    checks: tuple[str, ...]
    commands: tuple[SuggestedCommand, ...] = ()
    notes: tuple[str, ...] = ()
    caution: str | None = None


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _was_guessed(port: PortResult) -> bool:
    """
    True when Nmap named the service from its port-number table rather
    than a real probe response (`method == "table"`). That is exactly
    the case where the service name is least trustworthy, so guidance
    built on it has to say so.
    """
    return port.method == "table"


def _searchsploit_lead(port: PortResult) -> str | None:
    """
    Build a searchsploit lead from an identified product/version, or
    None if version detection didn't identify one. Phrased as a lead to
    verify, never as a confirmed finding - see the module docstring.
    """
    if not port.product:
        return None

    term = port.product
    if port.version:
        term = f"{term} {port.version}"

    return (
        f"{term}: look for known issues with 'searchsploit {term}'. "
        "Treat any hit as a lead to verify against this target, not a "
        "confirmed vulnerability - versions can be faked and distributions "
        "backport fixes."
    )


def _guessed_caution(port: PortResult, service_label: str) -> str | None:
    """
    The standard "confirm this first" heads-up, shared by every
    producer, for when the service was only guessed from the port
    number. Keeps the wording identical across services.
    """
    if not _was_guessed(port):
        return None
    return (
        "This service was guessed from the port number, not confirmed by a "
        f"probe. Enable service/version detection and scan again before "
        f"trusting that it is {service_label} - the suggestions here assume "
        "it is."
    )


# ---------------------------------------------------------------------------
# Per-service producers
# ---------------------------------------------------------------------------

_HTTP_SERVICES = {"http", "https", "http-proxy", "http-alt", "https-alt"}
_STANDARD_HTTP_PORTS = {80, 8080, 8000, 8888}
_STANDARD_HTTPS_PORTS = {443, 8443}


def _http_base_url(target: str, port: PortResult) -> tuple[str, bool]:
    """
    Build the base URL to put in example commands, and report whether
    the service is over TLS. The port is included unless it is the
    default for the scheme, so the command is correct to paste as-is.
    """
    is_tls = (
        port.tunnel == "ssl"
        or port.service in ("https", "https-alt")
        or port.port in _STANDARD_HTTPS_PORTS
    )
    scheme = "https" if is_tls else "http"

    default_port = 443 if is_tls else 80
    if port.port == default_port:
        return f"{scheme}://{target}", is_tls
    return f"{scheme}://{target}:{port.port}", is_tls


def _http_guidance(target: str, port: PortResult) -> Guidance:
    base, is_tls = _http_base_url(target, port)

    checks = [
        "Fingerprint the stack: which web server, framework and, if any, CMS.",
        "Brute-force for hidden paths and files - admin panels, backups, "
        "uploads.",
        "Read the page source, and check robots.txt and sitemap.xml for "
        "paths the site itself points at.",
    ]
    commands = [
        SuggestedCommand(
            f"whatweb {base}",
            "fingerprint the server, framework and any CMS",
            "whatweb",
        ),
        SuggestedCommand(
            f"gobuster dir -u {base} -w <wordlist>",
            "brute-force for hidden paths and files",
            "gobuster",
        ),
    ]
    notes = []

    if is_tls:
        checks.append(
            "Read the TLS certificate - its subject and SAN fields often "
            "leak internal hostnames worth adding to your scan and hosts "
            "file."
        )
        commands.append(
            SuggestedCommand(
                f"openssl s_client -connect {target}:{port.port}",
                "read the TLS certificate for hostnames",
                "openssl",
            )
        )

    standard = _STANDARD_HTTPS_PORTS if is_tls else _STANDARD_HTTP_PORTS
    if port.port not in standard:
        notes.append(
            f"Port {port.port} is an unusual place for a web service, which "
            "is a common home for admin panels, dev servers and APIs. Worth "
            "a close look."
        )

    lead = _searchsploit_lead(port)
    if lead:
        notes.append(lead)

    caution = None
    if _was_guessed(port):
        caution = (
            "This service was guessed from the port number, not confirmed by "
            "a probe. Enable service/version detection and scan again before "
            "trusting that it is really HTTP - the suggestions below assume "
            "it is."
        )

    return Guidance(
        what="A web service. The most common foothold on a lab box.",
        why=(
            "Web apps carry the widest range of issues: hidden pages, login "
            "forms, file uploads, and known flaws in the server or the app "
            "running on it."
        ),
        checks=tuple(checks),
        commands=tuple(commands),
        notes=tuple(notes),
        caution=caution,
    )


def _generic_guidance(target: str, port: PortResult) -> Guidance:
    """
    Fallback for any open service without its own producer yet, so no
    open port is ever left with nothing to say. Keeps to advice that is
    true for any service: confirm what it is, research its normal
    behaviour, and treat a known version as a lead.
    """
    service = port.service or "unknown"

    checks = [
        "Confirm what it is: if the service is unconfirmed, enable "
        "service/version detection and scan again.",
        "Research how this service normally behaves and its default "
        "configuration, so you can spot what is out of place.",
    ]
    notes = []

    lead = _searchsploit_lead(port)
    if lead:
        checks.append("Look up the identified product and version as a lead.")
        notes.append(lead)

    caution = None
    if _was_guessed(port):
        caution = (
            "The service name was guessed from the port number, not "
            "confirmed. Enable service/version detection and scan again "
            "before trusting it."
        )

    return Guidance(
        what=f"The {service} service on port {port.port}.",
        why=(
            "Any open port is a potential way in or an information leak, even "
            "where In the Dark has no specific playbook for it yet."
        ),
        checks=tuple(checks),
        commands=(),
        notes=tuple(notes),
        caution=caution,
    )


def _ftp_guidance(target: str, port: PortResult) -> Guidance:
    notes = []
    lead = _searchsploit_lead(port)
    if lead:
        notes.append(lead)

    return Guidance(
        what="File Transfer Protocol.",
        why=(
            "A frequent quick win: it often allows anonymous login, and the "
            "files it serves - or accepts, if the directory is writable - can "
            "hand you credentials, source code or a foothold."
        ),
        checks=(
            "Try an anonymous login (user 'anonymous', any password) and list "
            "what is there.",
            "Download anything readable and check it for credentials or clues.",
            "Test whether you can upload - a writable FTP root is sometimes a "
            "way onto the box.",
        ),
        commands=(
            SuggestedCommand(
                f"ftp {target}",
                "connect, then log in as 'anonymous' to test anonymous access",
                "ftp",
            ),
        ),
        notes=tuple(notes),
        caution=_guessed_caution(port, "FTP"),
    )


def _smb_guidance(target: str, port: PortResult) -> Guidance:
    notes = []
    lead = _searchsploit_lead(port)
    if lead:
        notes.append(lead)

    return Guidance(
        what="Windows file sharing (SMB/CIFS).",
        why=(
            "Commonly misconfigured on lab boxes. A null (unauthenticated) "
            "session can often list shares, users and the OS version, and "
            "sometimes read files outright."
        ),
        checks=(
            "List shares with a null session - no username or password.",
            "Connect to any interesting share and look for readable files.",
            "Enumerate users, groups and the OS version for later use.",
        ),
        commands=(
            SuggestedCommand(
                f"smbclient -L //{target}/ -N",
                "list shares with no credentials",
                "smbclient",
            ),
            SuggestedCommand(
                f"enum4linux -a {target}",
                "broad SMB enumeration: shares, users and OS",
                "enum4linux",
            ),
        ),
        notes=tuple(notes),
        caution=_guessed_caution(port, "SMB"),
    )


def _ssh_guidance(target: str, port: PortResult) -> Guidance:
    notes = []
    lead = _searchsploit_lead(port)
    if lead:
        notes.append(lead)

    return Guidance(
        what="Secure Shell - remote administration.",
        why=(
            "Almost always open and almost never the initial way in by itself: "
            "modern SSH is hard to attack blind, so don't burn time "
            "brute-forcing it. Its value is later, once you have found "
            "credentials elsewhere."
        ),
        checks=(
            "Record the version string and host key - useful for spotting a "
            "reused key or a known-vulnerable build.",
            "Note which authentication methods it offers (password versus "
            "key-only).",
            "Come back to it with any usernames or credentials you find on "
            "other services rather than brute-forcing it first.",
        ),
        commands=(
            SuggestedCommand(
                f"nc {target} {port.port}",
                "grab the SSH banner and version",
                "nc",
            ),
        ),
        notes=tuple(notes),
        caution=_guessed_caution(port, "SSH"),
    )


def _dns_guidance(target: str, port: PortResult) -> Guidance:
    notes = []
    lead = _searchsploit_lead(port)
    if lead:
        notes.append(lead)

    return Guidance(
        what="Domain Name System.",
        why=(
            "A misconfigured DNS server may allow a zone transfer, which dumps "
            "every record it holds - internal hostnames, subdomains and "
            "addresses you would otherwise never see. Quick to test and "
            "occasionally a jackpot."
        ),
        checks=(
            "Attempt a zone transfer - you need a domain name, taken from a TLS "
            "certificate, a web vhost or the box's own hostname.",
            "Do forward and reverse lookups to map names to addresses.",
            "Note the server software for known issues.",
        ),
        commands=(
            SuggestedCommand(
                f"dig axfr @{target} <domain>",
                "attempt a zone transfer (replace <domain> with a known name)",
                "dig",
            ),
        ),
        notes=tuple(notes),
        caution=_guessed_caution(port, "DNS"),
    )


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
#
# A plain lookup from service name to producer. Adding a service later
# is one (service set, producer) pair here plus one producer function
# above - no framework, no registration machinery. Service names are
# Nmap's own: DNS is "domain", Windows SMB is usually "microsoft-ds".

_SERVICE_PRODUCERS = (
    (_HTTP_SERVICES, _http_guidance),
    ({"ftp"}, _ftp_guidance),
    ({"microsoft-ds", "netbios-ssn", "smb"}, _smb_guidance),
    ({"ssh"}, _ssh_guidance),
    ({"domain", "dns"}, _dns_guidance),
)

_PRODUCERS = {
    service: producer
    for services, producer in _SERVICE_PRODUCERS
    for service in services
}


def guidance_for(target: str, port: PortResult) -> Guidance | None:
    """
    Return guidance for one open port, or None if there is nothing to
    advise on (a port that is not open). The service name is matched
    case-insensitively; anything without its own producer falls back to
    generic guidance, so an open port always gets something.
    """
    if port.state != "open":
        return None

    service = (port.service or "").lower()
    producer = _PRODUCERS.get(service, _generic_guidance)
    return producer(target, port)
