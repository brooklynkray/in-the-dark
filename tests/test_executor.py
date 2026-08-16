"""
Tests for executor.py - the only place In the Dark actually runs a
process.

None of these tests use Nmap or a live network target. They invoke
the current Python interpreter (sys.executable) running short inline
scripts via `-c`, which is a reliable, harmless "local process" that
behaves identically on Windows and Linux - unlike shell builtins such
as echo/sleep/cat, which differ (or don't exist) across platforms.
"""

import subprocess
import sys

import executor


def python_script(code):
    """An argv list that runs `code` under the current interpreter."""
    return [sys.executable, "-c", code]


# ---------------------------------------------------------------------------
# 1. Successful process
# ---------------------------------------------------------------------------

def test_successful_process_exits_zero_with_captured_output():
    argv = python_script(
        "import sys; sys.stdout.write('out-text'); "
        "sys.stderr.write('err-text')"
    )

    result = executor.run(argv)

    assert result.return_code == 0
    assert result.stdout == "out-text"
    assert result.stderr == "err-text"
    assert result.timed_out is False
    assert result.executable_not_found is False


# ---------------------------------------------------------------------------
# 2. Non-zero exit
# ---------------------------------------------------------------------------

def test_non_zero_exit_preserves_return_code_and_output():
    argv = python_script(
        "import sys; sys.stdout.write('partial-out'); "
        "sys.stderr.write('partial-err'); sys.exit(7)"
    )

    result = executor.run(argv)

    assert result.return_code == 7
    assert result.stdout == "partial-out"
    assert result.stderr == "partial-err"
    assert result.timed_out is False
    assert result.executable_not_found is False


# ---------------------------------------------------------------------------
# 3. Missing executable
# ---------------------------------------------------------------------------

def test_missing_executable_produces_structured_failure_not_a_traceback():
    argv = ["definitely-not-a-real-executable-in-the-dark-xyz123"]

    result = executor.run(argv)

    assert result.executable_not_found is True
    assert result.return_code is None
    assert result.timed_out is False


# ---------------------------------------------------------------------------
# 4. Timeout
# ---------------------------------------------------------------------------

def test_timeout_is_reported_and_does_not_hang():
    argv = python_script("import time; time.sleep(5)")

    result = executor.run(argv, timeout=0.2)

    assert result.timed_out is True
    assert result.return_code is None
    assert result.executable_not_found is False


# ---------------------------------------------------------------------------
# 5. argv integrity - shell metacharacters stay one literal argument
# ---------------------------------------------------------------------------

def test_shell_metacharacters_survive_as_one_literal_argument():
    hostile_arg = "hello && whoami"
    argv = python_script("import sys; sys.stdout.write(sys.argv[1])") + [
        hostile_arg
    ]

    result = executor.run(argv)

    # If a shell had interpreted this, "&&" would have chained a
    # second command instead of being handed to Python as data.
    assert result.return_code == 0
    assert result.stdout == hostile_arg


# ---------------------------------------------------------------------------
# 6. No shell execution - regression guard on the actual subprocess call
# ---------------------------------------------------------------------------

def test_run_invokes_subprocess_with_argv_list_and_shell_disabled(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(executor.subprocess, "run", fake_run)

    argv = python_script("print('unused - subprocess.run is mocked')")
    executor.run(argv)

    assert captured["argv"] == argv
    assert isinstance(captured["argv"], list)
    assert captured["kwargs"]["shell"] is False
