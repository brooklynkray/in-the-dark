#!/usr/bin/env python3
"""
cli.py
------

Centralised terminal presentation for In the Dark.

This module owns HOW the application looks in the terminal: the
startup banner, section headings, coloured status markers, and the
aligned layout of status/field lines.

It must NOT contain any application logic. Target validation, DNS
resolution and environment/privilege detection all belong to their
own modules (target.py, dns.py, environment.py) and are simply
*handed to* this module so it can be displayed consistently.

Typical usage from main.py:

    import cli

    cli.banner()
    cli.status("Checking Nmap", "OK", level="ok")

    cli.section("Target")
    cli.success("Target confirmed")
    cli.error("Invalid target.")
"""

import os
import sys
from typing import Literal


# ---------------------------------------------------------------------------
# Colour support
# ---------------------------------------------------------------------------
#
# Colour is a presentation detail, so the decision of *whether* to use
# it lives here rather than in main.py. The rule is kept simple:
#
#   - Colour is only used when stdout is a real, interactive terminal.
#     Output redirected to a file or piped to another program (e.g.
#     `python3 main.py > log.txt`) stays free of escape codes.
#   - The NO_COLOR environment variable (https://no-color.org/) is
#     respected if set, regardless of terminal support.
#
# Every function below still produces correct, readable output with
# colour disabled - only the ANSI codes change, never the text.

def _colour_enabled() -> bool:
    """Return True if it is safe to write ANSI colour codes to stdout."""
    if os.environ.get("NO_COLOR") is not None:
        return False

    # isatty() is the standard way to detect a real terminal, as
    # opposed to a pipe or a file redirect.
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_COLOUR = _colour_enabled()

_RESET = "\033[0m"
_STYLES = {
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}


def _style(text: str, *styles: str) -> str:
    """
    Wrap `text` in the given ANSI styles (e.g. "green", "bold").

    Returns `text` unchanged when colour is disabled, so every other
    function in this module can call this unconditionally without
    checking `_COLOUR` itself.
    """
    if not _COLOUR:
        return text

    codes = "".join(_STYLES[name] for name in styles if name in _STYLES)
    return f"{codes}{text}{_RESET}"


# ---------------------------------------------------------------------------
# ASCII banner
# ---------------------------------------------------------------------------

LOGO_LINES = [
    ' _____ _   _   _______ _    _ ______   _____          _____   _  __',
    '|_   _| \\ | | |__   __| |  | |  ____| |  __ \\   /\\   |  __ \\ | |/ /',
    '  | | |  \\| |    | |  | |__| | |__    | |  | | /  \\  | |__) || |/ /',
    '  | | | . ` |    | |  |  __  |  __|   | |  | |/ /\\ \\ |  _  / | |\\ \\',
    ' _| |_| |\\  |    | |  | |  | | |____  | |__| / ____ \\| | \\ \\ | |\\ \\',
    '|_____|_| \\_|    |_|  |_|  |_|______| |_____/_/    \\_\\_|  \\_\\|_|\\_\\',
]

_TAGLINE = (
    "GUIDED SECURITY RECONNAISSANCE",
    "& ENUMERATION",
)


def banner() -> None:
    """Print the startup ASCII logo followed by the tagline."""
    width = max(len(line) for line in LOGO_LINES)

    print()
    for line in LOGO_LINES:
        print(_style(line, "cyan", "bold"))

    print()
    for line in _TAGLINE:
        print(_style(line.center(width), "dim"))
    print()


# ---------------------------------------------------------------------------
# Structural elements
# ---------------------------------------------------------------------------

RULE_WIDTH = 60


def rule() -> None:
    """Print a plain horizontal divider."""
    print(_style("\u2500" * RULE_WIDTH, "dim"))


def section(title: str) -> None:
    """
    Print a top-level section heading, e.g.:

        ------------------------------------------------------------
        TARGET
        ------------------------------------------------------------

    (rendered with the same box-drawing rule as rule() above). Use
    this for the major stages of the flow (Target, Scan, Findings...).
    For a lighter heading *inside* an existing section, use
    subsection() instead - stacking two full rule blocks reads as
    visual noise rather than structure.
    """
    print()
    rule()
    print(_style(title.upper(), "bold"))
    rule()


def subsection(title: str) -> None:
    """
    Print a lightweight subheading, e.g.:

        Target information
        ------------------

    Used for structure *within* an existing section() block, where a
    full rule-bordered heading would be too heavy - e.g. "Target
    information" and "DNS information" inside the outer "TARGET"
    section. This intentionally matches the plain title-plus-underline
    style the project used before the CLI layer existed, just with
    consistent styling applied.
    """
    print()
    print(_style(title, "bold"))
    print(_style("-" * len(title), "dim"))


# ---------------------------------------------------------------------------
# Status messages
# ---------------------------------------------------------------------------
#
# These map directly onto the four status symbols used throughout the
# application: [+] success, [!] warning, [-] error, [*] info.

def success(message: str) -> None:
    """Print a success line, e.g. '[+] Target confirmed'."""
    print(f"{_style('[+]', 'green')} {message}")


def warning(message: str) -> None:
    """Print a warning line, e.g. '[!] Nmap not found on PATH'."""
    print(f"{_style('[!]', 'yellow')} {message}")


def error(message: str) -> None:
    """Print an error line, e.g. '[-] Invalid target.'"""
    print(f"{_style('[-]', 'red')} {message}")


def info(message: str) -> None:
    """Print an informational line, e.g. '[*] Exiting In the Dark.'"""
    print(f"{_style('[*]', 'cyan')} {message}")


def status(
    label: str,
    result: str,
    level: Literal["ok", "warn", "error"] = "ok",
) -> None:
    """
    Print an aligned startup-style status line, e.g.:

        [+] Checking privileges................. OK (kali, unprivileged)

    `result` is plain text supplied by the caller - this function only
    lays it out consistently, it never invents or checks the content.
    `level` picks the marker and colour: "ok" -> [+] green,
    "warn" -> [!] yellow, "error" -> [-] red.
    """
    markers = {
        "ok": ("[+]", "green"),
        "warn": ("[!]", "yellow"),
        "error": ("[-]", "red"),
    }
    symbol, colour = markers.get(level, markers["ok"])

    # Pad with dots so the result column stays aligned across status
    # lines even when labels are different lengths. A floor of 3 dots
    # keeps unusually long labels readable instead of colliding with
    # the result text.
    dots = "." * max(3, 44 - len(label))

    print(f"{_style(symbol, colour)} {label}{_style(dots, 'dim')} {result}")


# ---------------------------------------------------------------------------
# Structured data display
# ---------------------------------------------------------------------------

def field(label: str, value: str, width: int = 14) -> None:
    """
    Print an aligned "Label:  Value" line, e.g.:

        Target:       google.com
        Type:         hostname

    `width` sets where the value column starts, so a block of field()
    calls lines up automatically regardless of label length.
    """
    print(f"{(label + ':').ljust(width)}{value}")


def list_items(title: str, items: list[str]) -> None:
    """
    Print a titled, indented list, e.g.:

        Resolved addresses:
          10.10.10.22
          10.10.10.23

    No colour is applied, matching the plain print() calls this
    replaces - callers decide whether the list is worth showing at
    all (an empty list is a caller-level decision, not this
    function's to make).
    """
    print(f"{title}:")

    for item in items:
        print(f"  {item}")


def menu(options: list[tuple[str, str]]) -> None:
    """
    Print a list of numbered/keyed choices, e.g.:

        [1] Yes, continue
        [2] Enter different target
        [3] Exit

    `options` is a sequence of (key, label) pairs. This only prints
    the menu - reading and interpreting the choice stays in main.py.
    """
    for key, label in options:
        print(f"[{key}] {label}")


if __name__ == "__main__":
    # Running `python3 cli.py` directly demonstrates every presentation
    # element without needing the rest of the application - handy for
    # checking how things look after a styling change.
    banner()

    rule()
    status("Initialising environment", "OK")
    status("Checking privileges", "OK (demo, unprivileged)")
    status("Checking Nmap", "NOT FOUND", level="warn")
    rule()
    print("\nReady.\n")

    section("Target")
    subsection("Target information")
    field("Target", "example.com")
    field("Type", "hostname")
    subsection("DNS information")
    print("Resolved addresses:")
    print("  93.184.216.34")
    print()
    success("Target confirmed")
    warning("This is a warning")
    error("This is an error")
    info("This is an informational message")
    print()
    menu([
        ("1", "Yes, continue"),
        ("2", "Enter different target"),
        ("3", "Exit"),
    ])
