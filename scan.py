#!/usr/bin/env python3
"""
scan.py
-------

Scan configuration and command construction for In the Dark.

This module is the single place where user intent - guided questions
today, profiles or expert/manual mode later - is turned into a
concrete Nmap invocation. It owns:

- ScanConfig: a frozen, typed description of what was asked for.
- build_argv(): a pure function turning a ScanConfig and a validated
  TargetInfo into an argv list. It never touches a shell and never
  runs anything.
- Teaching metadata, used by the UI layer to explain what each option
  does, so presentation code never invents its own description of
  what a flag means.

Nothing in this module calls subprocess. Execution is a later
increment - this one stops at "here is the command that would run".
"""

from dataclasses import dataclass
from enum import Enum


# ---------------------------------------------------------------------------
# Nmap flag constants
# ---------------------------------------------------------------------------
#
# Defined once so build_argv() and the teaching metadata below always
# agree - a flag is only ever spelled out in one place. A test asserts
# the metadata and build_argv() stay in sync.

FLAG_COMMON_PORTS = "-F"
FLAG_ALL_TCP_PORTS = "-p-"
FLAG_SERVICE_DETECTION = "-sV"


class PortScope(Enum):
    """Which ports Nmap should scan."""

    COMMON = "common"
    TOP_1000 = "top_1000"
    ALL_TCP = "all_tcp"


@dataclass(frozen=True)
class ScanConfig:
    """
    A validated, immutable description of what kind of scan the user
    asked for. This is the single object that guided questions,
    profiles, and (later) expert/manual mode all converge on before
    build_argv() turns it into a command.

    The defaults here match Nmap's own sensible default (top 1000
    TCP ports) plus service detection, since that is the most useful
    starting point for a learner - but callers must still show the
    chosen values, never assume them silently.
    """

    port_scope: PortScope = PortScope.TOP_1000
    service_detection: bool = True


# ---------------------------------------------------------------------------
# Teaching metadata
# ---------------------------------------------------------------------------
#
# Plain data describing each capability, for the UI to present. This
# is deliberately not a plugin/capability framework: build_argv()
# below does not read from this structure or iterate over it, it only
# shares the flag constants above with it.

@dataclass(frozen=True)
class CapabilityInfo:
    name: str
    what: str
    why: str
    flag: str
    cost: str


PORT_SCOPE_INFO = {
    PortScope.COMMON: CapabilityInfo(
        name="Common/fast",
        what="Scans Nmap's ~100 most common ports.",
        why="A quick first look at a host when speed matters more "
            "than full coverage.",
        flag=FLAG_COMMON_PORTS,
        cost="Fastest option, but may miss services on uncommon "
             "ports.",
    ),
    PortScope.TOP_1000: CapabilityInfo(
        name="Top 1000 (default)",
        what="Scans Nmap's own default list of the 1000 most common "
             "TCP ports.",
        why="Nmap's normal balance of speed and coverage - a "
            "reasonable default for most reconnaissance.",
        # Nmap scans its default port list when no -p/-F/-p- flag is
        # given, so this option intentionally has no flag of its own.
        flag="",
        cost="Slower than Common; still misses ports outside the "
             "top 1000.",
    ),
    PortScope.ALL_TCP: CapabilityInfo(
        name="All TCP ports",
        what="Scans all 65535 TCP ports.",
        why="Full coverage when you need to be sure nothing was "
            "missed, e.g. before a thorough assessment.",
        flag=FLAG_ALL_TCP_PORTS,
        cost="Significantly slower than Common or Top 1000.",
    ),
}

SERVICE_DETECTION_INFO = CapabilityInfo(
    name="Service/version detection",
    what="Probes open ports to identify the service and version "
         "running on them.",
    why="Turns a bare port number into an actionable finding - "
        "knowing you're looking at OpenSSH 8.2 rather than just "
        "'something on port 22'.",
    flag=FLAG_SERVICE_DETECTION,
    cost="Adds time per open port, since it sends extra probes.",
)


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------

def build_argv(target_info, scan_config):
    """
    Turn a validated TargetInfo and a ScanConfig into an Nmap argv
    list, in canonical order:

        1. nmap
        2. port-scope option, if one exists
        3. service/version detection, if enabled
        4. target

    Pure and deterministic: no subprocess, no printing, no shell
    involvement. The target is always appended as exactly one
    element at the end - never concatenated with flags, never split,
    never passed through a shell. Later capabilities (timing, scan
    technique, custom ports, NSE, ...) get inserted as further
    explicit steps in this same sequence, at defined positions -
    this function is not meant to become a loop over metadata.
    """

    argv = ["nmap"]

    if scan_config.port_scope == PortScope.COMMON:
        argv.append(FLAG_COMMON_PORTS)
    elif scan_config.port_scope == PortScope.ALL_TCP:
        argv.append(FLAG_ALL_TCP_PORTS)
    # TOP_1000 is Nmap's own default port scope, so it adds no flag.

    if scan_config.service_detection:
        argv.append(FLAG_SERVICE_DETECTION)

    argv.append(target_info.value)

    return argv
