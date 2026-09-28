# In the Dark

A guided cybersecurity reconnaissance and enumeration tool built for learning.

## Purpose

In the Dark is designed to help security learners understand what to do after discovering a host, port, or service during authorised security testing.

Rather than simply running tools and displaying their output, the application aims to explain:

- What was discovered
- Why it matters
- What would normally be investigated next
- Which tools or techniques could be appropriate
- What the learner should record
- Whether a service appears normal or unusual for its port

## Project Goals

The project will initially focus on:

1. Host and port discovery
2. Service and version detection
3. Service-specific enumeration guidance
4. Web enumeration
5. Structured note taking
6. Findings and evidence tracking
7. Reporting

The long-term goal is to develop a guided workflow from reconnaissance through investigation and documentation.

## Current Status

Stages 1 and 2 (host/port discovery and service/version detection) are built around a guided Nmap workflow:

1. Enter and confirm a target (IPv4, IPv6 or hostname, with DNS enrichment)
2. Answer guided questions: scan technique, host discovery (`-Pn`), port scope, service detection, OS detection, timing
3. Review a preview of the exact command and what each choice does, then give explicit consent
4. Nmap runs; raw output is shown, plus a structured summary parsed from Nmap's XML
5. The structured results are saved as JSON in `results/` for later stages to load

## Requirements

- Python 3.11 or newer
- Nmap on your `PATH`
- SYN scans (`-sS`) and OS detection (`-O`) need root. In the Dark itself always runs as your normal user; for those scans it offers to run only Nmap with `sudo`, which needs your user to be allowed to use sudo

On Arch-based systems (including Omarchy):

```bash
sudo pacman -S nmap python python-pytest
```

On Debian-based systems (including Kali):

```bash
sudo apt install nmap python3 python3-pytest
```

## Usage

```bash
python3 main.py
```

## Running the Tests

```bash
python3 -m pytest
```

Use `python3 -m pytest` rather than bare `pytest`, so the project root is on the import path. The tests never run Nmap or touch the network. GitHub Actions runs the same suite on Python 3.11, 3.12 and 3.13 for every push and pull request.

## Security Design

This is a tool that runs other programs and handles data from hosts it scans, so a few decisions are deliberate:

- **No shell, ever.** Commands are built as argument lists and run with `shell=False`. A target like `10.10.10.5; rm -rf ~` reaches Nmap as one (invalid) argument, not a second command.
- **No free-text Nmap flags.** Every option maps to a fixed, allow-listed flag. A free-text flag box would be an injection surface even without a shell (for example `--script` or output options).
- **Targets are validated before use.** Only IP addresses and well-formed hostnames are accepted, so a value that starts with `-` can never be read by Nmap as an option.
- **Nmap output is untrusted input.** Banners and product strings come from the target. The XML parser never crashes on malformed or unexpected input, and treats field contents as inert data.
- **Only Nmap is ever elevated, and only with consent.** When a scan needs root, the preview shows the exact command, `sudo -n -- nmap ...`, and the approval option says so. After approval, `sudo -v` asks for your password in the open; the scan then runs with `-n`, so sudo can never sit waiting on a hidden password prompt. Input handling, parsing of untrusted Nmap output and saving results never run as root. Because Nmap options such as `--script` can run arbitrary code, the no-free-text-flags rule is what stops a root-run Nmap from becoming a root shell.
- **Temporary XML output** goes in a private, unpredictably named `mkdtemp` directory (mode 0700) and is always removed afterwards. A shared `/tmp` file would be refused to a root-run Nmap by the kernel's `fs.protected_regular` hardening.
- **Saved results** get generated file names (never built from the target, so no path traversal), are created without overwriting anything, and are readable only by your user (`0600`). Odd characters from the target are stored as `\uXXXX` escapes.

## Results Files

Each completed scan is saved as `results/scan-<UTC timestamp>-<random>.json`. The file holds a `schema_version`, the target, the scan choices, the exact command that ran, and the parsed results (ports with service, product, version, extra info, SSL tunnel and CPE identifiers; addresses; hostnames; OS guesses; and whether the host seemed down). `results/*.json` is git-ignored, so scan data is never committed by accident.

## Disclaimer

In the Dark is intended for authorised security testing, cybersecurity education, and defensive use only.

Only scan systems you own or have explicit permission to test.
