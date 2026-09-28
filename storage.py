#!/usr/bin/env python3
"""
storage.py
----------

Saving a finished scan to disk as JSON, so later stages (service
enumeration guidance, notes, findings, reporting) have something to
load instead of re-running Nmap.

This module owns the one place In the Dark writes results files. It
is split into two parts on purpose:

- build_scan_record(): pure - turns the target, the approved
  ScanConfig, the exact argv that ran and the parsed ScanResult into
  a plain dict. No filesystem, easy to test.
- save_scan_record(): the only function here that touches the disk.

Security decisions, stated so they're easy to explain:

- The file name is generated (UTC timestamp + random suffix) and is
  NEVER built from the target or any other user input. A target such
  as "../../home/you/.bashrc" can't steer where the file lands, so
  path traversal isn't possible by construction. The final path is
  still checked to sit directly inside the results directory, as
  defence in depth.
- Files are created with os.open(O_CREAT | O_EXCL) and mode 0600:
  O_EXCL refuses to overwrite anything already at that path (including
  a planted symlink), and 0600 means only your user can read the
  results. Scan results describe a target's exposure, so they're
  treated as sensitive by default.
- json.dump() keeps its default ensure_ascii=True, so any odd
  characters in target-supplied strings (banners, product names) are
  written as \\uXXXX escapes. Running `cat` on a results file can't
  feed control characters to your terminal.

The record carries a `schema_version`. If the shape ever changes,
bump it, so a loader in a later stage can tell old files from new.
"""

import dataclasses
import enum
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1

# Next to the code rather than the current working directory, so
# results land in the same place wherever the tool is started from.
# .gitignore already excludes results/*.json from commits.
DEFAULT_RESULTS_DIR = Path(__file__).resolve().parent / "results"


def _to_jsonable(value):
    """
    Recursively convert dataclasses, enums and tuples into plain JSON
    types. Enums are stored by their .value ("syn", "t4") so the file
    doesn't depend on Python class names.
    """

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _to_jsonable(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }

    if isinstance(value, enum.Enum):
        return value.value

    if isinstance(value, (list, tuple)):
        return [_to_jsonable(item) for item in value]

    if isinstance(value, dict):
        return {key: _to_jsonable(item) for key, item in value.items()}

    return value


def build_scan_record(target_info, scan_config, argv, scan_result, created_at):
    """
    Build the dict that gets saved for one scan.

    `argv` is the exact command that ran, including the -oX path to
    the (by now deleted) temporary XML file - it is kept verbatim as
    an honest record of what was executed. `xml_output_path` is left
    out of the scan configuration, since it's tool plumbing rather
    than a choice the learner made.
    """

    config = _to_jsonable(scan_config)
    config.pop("xml_output_path", None)

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "in-the-dark",
        "created_at": created_at.isoformat(),
        "target": _to_jsonable(target_info),
        "scan_config": config,
        "command": list(argv),
        "host_seems_down": scan_result.host_seems_down,
        "result": _to_jsonable(scan_result),
    }


def _results_file_name(created_at):
    """
    Generate a results file name from the time and a random suffix.
    Never derived from user input - see the module docstring.
    """

    timestamp = created_at.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"scan-{timestamp}-{secrets.token_hex(4)}.json"


def save_scan_record(record, created_at, results_dir=DEFAULT_RESULTS_DIR):
    """
    Write `record` as JSON to a new file in `results_dir` and return
    its Path.

    Raises OSError (including FileExistsError) if the directory can't
    be created or the file can't be written - the caller decides how
    to report that, since a failed save must not crash a scan that
    already finished.
    """

    results_dir = Path(results_dir)
    results_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    path = results_dir / _results_file_name(created_at)

    # Defence in depth: the name is generated, so this should always
    # hold - but if a future change ever lets input reach the name,
    # this refuses to write anywhere outside the results directory.
    if path.resolve().parent != results_dir.resolve():
        raise OSError(f"Refusing to write outside {results_dir}: {path}")

    file_descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    with os.fdopen(file_descriptor, "w", encoding="utf-8") as results_file:
        json.dump(record, results_file, indent=2)
        results_file.write("\n")

    return path


def now_utc():
    """The current time in UTC. Its own function so tests can replace it."""

    return datetime.now(timezone.utc)
