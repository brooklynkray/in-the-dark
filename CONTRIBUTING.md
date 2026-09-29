# Contributing to In the Dark

Thanks for your interest. In the Dark is a guided reconnaissance and enumeration
tool built for learning, used only in authorised environments: your own labs,
TryHackMe, CTFs, or systems you have explicit permission to test. Please keep
contributions in that spirit.

## Before you start

Read the **Security Design** section of the README. This tool runs other
programs and handles data from hosts it scans, so its security decisions are
deliberate. Contributions are expected to uphold them, not work around them.

## Development setup

- Python 3.11 or newer, and Nmap on your `PATH`. See the README's Requirements
  section for the exact install commands on Arch and Debian/Kali.
- Dev dependencies are pinned in `requirements-dev.txt` (pytest).
- Run the tool:
```bash
  python3 main.py
```
- Run the tests:
```bash
  python3 -m pytest
```
  Use `python3 -m pytest`, not bare `pytest`, so the project root is on the
  import path. The tests never run Nmap or touch the network. CI runs the same
  suite on Python 3.11, 3.12 and 3.13 for every push and pull request.

## Security expectations for changes

If your change touches how commands are run, how input is handled, privilege, or
file writes, it must hold the line on these:

- **No shell.** Build commands as argument lists, run with `shell=False`. Never
  interpolate user input into a command string.
- **No free-text tool flags.** Map every option to a fixed, allow-listed flag. A
  free-text flag box is an injection surface even without a shell.
- **Validate input at the boundary.** Targets, ports and filenames are checked
  before use, so a value starting with `-` can't be read as an option.
- **Treat external tool output as untrusted.** Nmap output and service banners
  come from the scanned host. Parse defensively; never crash on malformed input.
- **Least privilege.** Only Nmap is ever elevated, and only with explicit
  consent. Input handling, parsing and saving never run as root.
- **No path traversal.** Result filenames are generated, never built from the target.

Call any of these out in your pull request so it's easy to review.

## Pull requests

- Branch off `main` with a topic branch: `feat/...`, `fix/...` or `docs/...`.
- Small, logical commits with messages that say what changed and why.
- Make sure `python3 -m pytest` passes before you open the PR.
- Say what you changed, why, and how you tested it.
