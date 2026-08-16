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

No shell, no os.system(), no os.popen(), no command-string
construction, no privilege escalation, no output parsing. What Nmap
printed is returned as-is for the caller to display.
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
