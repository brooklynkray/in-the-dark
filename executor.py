#!/usr/bin/env python3
"""
executor.py
-----------

Process execution for In the Dark.

This module owns the one place an argv list is actually run. It takes
the exact list[str] scan.build_argv() produced and nothing else - no
TargetInfo, no ScanConfig - so it cannot construct or alter a command,
only execute one that has already been built, previewed, and
consented to.

- ExecutionResult: an immutable, structured outcome that makes normal
  success, a non-zero exit, a missing executable, and a timeout
  distinguishable without parsing an exception string.
- run(): executes argv via subprocess with shell=False, always.
- authenticate_sudo(): runs the fixed command "sudo -v" so the user
  can enter their password before a scan that was approved to run
  Nmap with sudo. It takes no arguments, so nothing can be added to
  that command.

No shell, no os.system(), no os.popen(), no command-string
construction, no output parsing. This module never decides to use
sudo: a sudo prefix only ever arrives as part of an argv the user has
already previewed and approved. What Nmap printed is returned as-is
for the caller to display.
"""

import subprocess
from dataclasses import dataclass

# A process timeout, not a scan timeout - this is "give up waiting on
# the OS process" (used verbatim by callers today), not Nmap's own
# -T0..-T5 timing templates, which are a separate, later concept.
DEFAULT_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class ExecutionResult:
    """
    The outcome of running one argv list.

    `return_code` is None whenever no process actually finished
    (executable not found, or it timed out) - callers should check
    `executable_not_found` and `timed_out` first, not infer the
    outcome from `return_code` alone.
    """

    return_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    executable_not_found: bool


def run(argv, timeout=DEFAULT_TIMEOUT_SECONDS):
    """
    Execute argv and return a structured ExecutionResult.

    argv is passed to subprocess.run() exactly as given - a list,
    with shell=False - never joined into a string, never re-parsed,
    never modified. This function has no idea what argv represents;
    it is not Nmap-specific.
    """

    try:
        completed = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return ExecutionResult(
            return_code=None,
            stdout="",
            stderr="",
            timed_out=False,
            executable_not_found=True,
        )
    except subprocess.TimeoutExpired as error:
        return ExecutionResult(
            return_code=None,
            stdout=error.stdout or "",
            stderr=error.stderr or "",
            timed_out=True,
            executable_not_found=False,
        )

    return ExecutionResult(
        return_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        timed_out=False,
        executable_not_found=False,
    )


def authenticate_sudo():
    """
    Ask sudo to authenticate this user, interactively, before a scan
    that needs root. Returns True if sudo accepted the user, False if
    it refused (wrong password, not allowed to use sudo) or sudo isn't
    installed.

    Deliberately not captured: sudo's password prompt has to reach the
    user's terminal. The scan itself then runs with "sudo -n", which
    never prompts, so a password prompt can never be hidden inside
    captured output or eat into the scan timeout. There is no timeout
    here either - sudo applies its own password timeout.
    """

    try:
        completed = subprocess.run(["sudo", "-v"], shell=False)
    except FileNotFoundError:
        return False

    return completed.returncode == 0
