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

Nothing in this module calls subprocess - execution lives in
executor.py, which receives only the argv list this module builds.
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
FLAG_TIMING_T0 = "-T0"
FLAG_TIMING_T1 = "-T1"
FLAG_TIMING_T2 = "-T2"
FLAG_TIMING_T4 = "-T4"
FLAG_TIMING_T5 = "-T5"
FLAG_TECHNIQUE_CONNECT = "-sT"
FLAG_TECHNIQUE_SYN = "-sS"
FLAG_OS_DETECTION = "-O"


class PortScope(Enum):
    """Which ports Nmap should scan."""

    COMMON = "common"
    TOP_1000 = "top_1000"
    ALL_TCP = "all_tcp"


class Timing(Enum):
    """Nmap's -T0 (slowest/stealthiest) through -T5 (fastest) timing templates."""

    T0 = "t0"
    T1 = "t1"
    T2 = "t2"
    T3 = "t3"
    T4 = "t4"
    T5 = "t5"


class Technique(Enum):
    """
    How Nmap probes each port: a full TCP handshake or a half-open
    SYN probe. UDP is a separate, additive concept in real Nmap usage
    (it combines with a TCP technique rather than replacing it), so
    it does not belong as a third member of this enum - it should
    become its own field if/when it's added.
    """

    CONNECT = "connect"
    SYN = "syn"


@dataclass(frozen=True)
class ScanConfig:
    """
    A validated, immutable description of what kind of scan the user
    asked for. This is the single object that guided questions,
    profiles, and (later) expert/manual mode all converge on before
    build_argv() turns it into a command.

    The defaults here match Nmap's own sensible defaults for port
    scope (top 1000 TCP ports) and timing (normal), plus service
    detection. The technique default (Connect) is a deliberate
    exception: Nmap's own default technique depends on runtime
    privilege, which this dataclass has no way to know and shouldn't -
    Connect is instead the only technique that works identically in
    every environment, which matters more for a learner's default
    than mirroring Nmap's own conditional choice. OS detection
    defaults to disabled for the same reason: it requires the same
    elevated privileges as a SYN scan, so defaulting it on would
    undermine the point of choosing an always-executable technique
    default in the first place. Callers must still show every chosen
    value, never assume it silently.
    """

    port_scope: PortScope = PortScope.TOP_1000
    service_detection: bool = True
    timing: Timing = Timing.T3
    technique: Technique = Technique.CONNECT
    os_detection: bool = False


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
        name="Top 1000",
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

OS_DETECTION_INFO = CapabilityInfo(
    name="OS detection",
    what="Analyses subtle differences in how the target responds to "
         "probes to guess its operating system.",
    why="Helps narrow down what the target is likely running, which "
        "shapes what to investigate next.",
    flag=FLAG_OS_DETECTION,
    cost="Requires the same raw-packet privileges as a SYN scan "
         "(root on Linux/macOS, Administrator on Windows) - without "
         "them, Nmap refuses to run it and exits with a privilege "
         "error. Even with privileges, results are a best guess and "
         "are most reliable when the scan found at least one open "
         "and one closed port to compare.",
)

TIMING_INFO = {
    Timing.T0: CapabilityInfo(
        name="T0 - Paranoid",
        what="The slowest timing template, spacing probes minutes "
             "apart.",
        why="Used to minimise the chance of triggering an IDS - "
            "rarely appropriate outside dedicated evasion practice.",
        flag=FLAG_TIMING_T0,
        cost="Extremely slow; a full scan can take hours. Combined "
             "with a large scan, this will likely exceed In the "
             "Dark's current 300-second execution timeout, so the "
             "scan may be stopped before it finishes.",
    ),
    Timing.T1: CapabilityInfo(
        name="T1 - Sneaky",
        what="A very slow timing template intended to reduce "
             "detection likelihood.",
        why="Similar goal to Paranoid but with slightly less "
            "spacing between probes.",
        flag=FLAG_TIMING_T1,
        cost="Very slow. Combined with a large scan, this will "
             "likely exceed In the Dark's current 300-second "
             "execution timeout, so the scan may be stopped before "
             "it finishes.",
    ),
    Timing.T2: CapabilityInfo(
        name="T2 - Polite",
        what="Slows down to use less bandwidth and target resources "
             "than the default.",
        why="Useful on fragile networks or when you want to reduce "
            "load on the target.",
        flag=FLAG_TIMING_T2,
        cost="Noticeably slower than the default; large scans may "
             "take a while longer to complete.",
    ),
    Timing.T3: CapabilityInfo(
        name="T3 - Normal",
        what="Nmap's own default timing - no artificial delay added "
             "between probes.",
        why="A reasonable balance of speed and reliability for most "
            "reconnaissance, and the least surprising choice since "
            "it matches Nmap's own default behaviour.",
        # Nmap uses this timing when no -T flag is given, so this
        # option intentionally has no flag of its own.
        flag="",
        cost="No particular trade-off - this is Nmap's baseline "
             "speed.",
    ),
    Timing.T4: CapabilityInfo(
        name="T4 - Aggressive",
        what="Speeds scanning up, assuming a reasonably fast and "
             "reliable network.",
        why="Common on labs/CTFs and other low-latency environments "
            "where speed matters more than subtlety.",
        flag=FLAG_TIMING_T4,
        cost="More likely to overwhelm a slow or heavily rate-"
             "limited target than the default.",
    ),
    Timing.T5: CapabilityInfo(
        name="T5 - Insane",
        what="The fastest timing template, sacrificing accuracy for "
             "speed.",
        why="Only appropriate on very fast, reliable networks where "
            "a short scan time matters more than complete results.",
        flag=FLAG_TIMING_T5,
        cost="Most likely of all templates to produce inaccurate or "
             "incomplete results on anything but an ideal network.",
    ),
}

TECHNIQUE_INFO = {
    Technique.CONNECT: CapabilityInfo(
        name="TCP Connect",
        what="Completes a full TCP three-way handshake with each "
             "port, like a normal application connection.",
        why="Works without any special privileges, so it runs in "
            "any environment - including this tool's own default.",
        flag=FLAG_TECHNIQUE_CONNECT,
        cost="Slower and easier to log than a SYN scan, since every "
             "port gets a fully completed connection.",
    ),
    Technique.SYN: CapabilityInfo(
        name="TCP SYN",
        what="Sends a SYN packet and inspects the response without "
             "completing the handshake (a 'half-open' scan).",
        why="Faster and stealthier than a full Connect scan, and is "
            "Nmap's own preferred technique when it's available.",
        flag=FLAG_TECHNIQUE_SYN,
        cost="Requires raw-packet privileges (root on Linux/macOS, "
             "Administrator on Windows). Without them, Nmap refuses "
             "to run this scan and exits with a privilege error - it "
             "will not silently fall back to a Connect scan.",
    ),
}


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------

def build_argv(target_info, scan_config):
    """
    Turn a validated TargetInfo and a ScanConfig into an Nmap argv
    list, in canonical order:

        1. nmap
        2. scan technique
        3. port-scope option, if one exists
        4. service/version detection, if enabled
        5. OS detection, if enabled
        6. timing option, if one exists
        7. target

    Pure and deterministic: no subprocess, no printing, no shell
    involvement, no privilege awareness - this function has no idea
    whether the current session can actually run the technique it's
    told to emit, and it must never guess. Unlike port scope and
    timing, the scan technique has no "Nmap default" that can be
    represented by omitting a flag: Nmap's own default depends on
    runtime privilege, which this function deliberately knows
    nothing about. Both techniques therefore always emit an explicit
    flag, so the previewed and executed command can never silently
    differ depending on who runs it.

    The target is always appended as exactly one element at the end -
    never concatenated with flags, never split, never passed through
    a shell. Later capabilities (custom ports, NSE, ...) get inserted
    as further explicit steps in this same sequence, at defined
    positions - this function is not meant to become a loop over
    metadata.
    """

    argv = ["nmap"]

    if scan_config.technique == Technique.CONNECT:
        argv.append(FLAG_TECHNIQUE_CONNECT)
    elif scan_config.technique == Technique.SYN:
        argv.append(FLAG_TECHNIQUE_SYN)

    if scan_config.port_scope == PortScope.COMMON:
        argv.append(FLAG_COMMON_PORTS)
    elif scan_config.port_scope == PortScope.ALL_TCP:
        argv.append(FLAG_ALL_TCP_PORTS)
    # TOP_1000 is Nmap's own default port scope, so it adds no flag.

    if scan_config.service_detection:
        argv.append(FLAG_SERVICE_DETECTION)

    if scan_config.os_detection:
        argv.append(FLAG_OS_DETECTION)

    if scan_config.timing == Timing.T0:
        argv.append(FLAG_TIMING_T0)
    elif scan_config.timing == Timing.T1:
        argv.append(FLAG_TIMING_T1)
    elif scan_config.timing == Timing.T2:
        argv.append(FLAG_TIMING_T2)
    elif scan_config.timing == Timing.T4:
        argv.append(FLAG_TIMING_T4)
    elif scan_config.timing == Timing.T5:
        argv.append(FLAG_TIMING_T5)
    # T3 is Nmap's own default timing template, so it adds no flag.

    argv.append(target_info.value)

    return argv
