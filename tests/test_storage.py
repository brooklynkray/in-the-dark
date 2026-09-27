"""
Tests for storage.py - building and saving scan records as JSON.

Every test writes into pytest's tmp_path, never the real results/
directory, and nothing here runs Nmap.
"""

import json
import os
import re
import stat
from datetime import datetime, timezone

import pytest

import main
import results
import scan
import storage
import target

CREATED_AT = datetime(2026, 9, 28, 1, 2, 3, tzinfo=timezone.utc)

TARGET = target.TargetInfo(
    value="lab.thm", type="hostname", resolved_addresses=["10.10.10.5"]
)

CONFIG = scan.ScanConfig(
    technique=scan.Technique.SYN,
    timing=scan.Timing.T4,
    skip_host_discovery=True,
    xml_output_path="/tmp/in-the-dark-abc.xml",
)

SCAN_RESULT = results.ScanResult(
    host=results.HostResult(
        status="up",
        ports=(
            results.PortResult(
                22, "tcp", "open", "ssh", "OpenSSH", "8.2p1",
                cpes=("cpe:/a:openbsd:openssh:8.2p1",),
            ),
        ),
        os_matches=(results.OsMatch("Linux 5.4", 96),),
    ),
    hosts_up=1,
    hosts_down=0,
    exit_status="success",
)


def build_record(target_info=TARGET, scan_result=SCAN_RESULT):
    argv = scan.build_argv(target_info, CONFIG)
    return storage.build_scan_record(
        target_info, CONFIG, argv, scan_result, CREATED_AT
    )


# ---------------------------------------------------------------------------
# build_scan_record() - pure
# ---------------------------------------------------------------------------

def test_record_has_schema_version_and_metadata():
    record = build_record()
    assert record["schema_version"] == storage.SCHEMA_VERSION
    assert record["tool"] == "in-the-dark"
    assert record["created_at"] == "2026-09-28T01:02:03+00:00"


def test_record_stores_enums_by_value_and_drops_xml_plumbing():
    config = build_record()["scan_config"]
    assert config["technique"] == "syn"
    assert config["timing"] == "t4"
    assert config["port_scope"] == "top_1000"
    assert config["skip_host_discovery"] is True
    assert "xml_output_path" not in config


def test_record_keeps_the_exact_command_that_ran():
    record = build_record()
    assert record["command"] == scan.build_argv(TARGET, CONFIG)


def test_record_keeps_target_and_nested_results():
    record = build_record()
    assert record["target"]["value"] == "lab.thm"
    assert record["target"]["resolved_addresses"] == ["10.10.10.5"]
    port = record["result"]["host"]["ports"][0]
    assert port["port"] == 22
    assert port["cpes"] == ["cpe:/a:openbsd:openssh:8.2p1"]
    assert record["result"]["host"]["os_matches"][0]["accuracy"] == 96
    assert record["host_seems_down"] is False


def test_record_for_down_host_without_host_element():
    down = results.ScanResult(host=None, hosts_up=0, hosts_down=1)
    record = build_record(scan_result=down)
    assert record["result"]["host"] is None
    assert record["host_seems_down"] is True


def test_record_is_json_serialisable():
    json.dumps(build_record())  # must not raise


# ---------------------------------------------------------------------------
# save_scan_record() - the only disk-touching code
# ---------------------------------------------------------------------------

def test_save_writes_readable_json_into_results_dir(tmp_path):
    results_dir = tmp_path / "results"
    record = build_record()

    path = storage.save_scan_record(record, CREATED_AT, results_dir)

    assert path.parent == results_dir
    assert json.loads(path.read_text(encoding="utf-8")) == record


def test_file_name_is_generated_never_derived_from_the_target(tmp_path):
    # A path-traversal-shaped value can't come through target.py's
    # validation, but storage must not rely on that.
    hostile = target.TargetInfo(value="../../../etc/cron.d/x", type="hostname")
    path = storage.save_scan_record(
        build_record(target_info=hostile), CREATED_AT, tmp_path
    )

    assert path.parent == tmp_path
    assert re.fullmatch(r"scan-20260928T010203Z-[0-9a-f]{8}\.json", path.name)


def test_two_saves_never_share_a_file(tmp_path):
    first = storage.save_scan_record(build_record(), CREATED_AT, tmp_path)
    second = storage.save_scan_record(build_record(), CREATED_AT, tmp_path)
    assert first != second


def test_save_refuses_to_overwrite_an_existing_file(monkeypatch, tmp_path):
    monkeypatch.setattr(storage.secrets, "token_hex", lambda n: "deadbeef")
    storage.save_scan_record(build_record(), CREATED_AT, tmp_path)

    with pytest.raises(FileExistsError):
        storage.save_scan_record(build_record(), CREATED_AT, tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_saved_file_and_new_directory_are_owner_only(tmp_path):
    results_dir = tmp_path / "results"
    path = storage.save_scan_record(build_record(), CREATED_AT, results_dir)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # mkdir's mode is filtered by the umask, so only assert that group
    # and others got nothing beyond what 0700 allows.
    assert stat.S_IMODE(results_dir.stat().st_mode) & 0o077 == 0


def test_target_supplied_control_characters_are_escaped_in_the_file(tmp_path):
    sneaky = results.ScanResult(
        host=results.HostResult(
            status="up",
            ports=(results.PortResult(
                80, "tcp", "open", "http", "evil\u009b31m‮", None
            ),),
        ),
    )
    path = storage.save_scan_record(
        build_record(scan_result=sneaky), CREATED_AT, tmp_path
    )
    raw = path.read_text(encoding="utf-8")

    assert "\u009b" not in raw and "‮" not in raw
    assert "\\u009b" in raw and "\\u202e" in raw
    # ...and it still round-trips to the original value.
    port = json.loads(raw)["result"]["host"]["ports"][0]
    assert port["product"] == "evil\u009b31m‮"


# ---------------------------------------------------------------------------
# main.save_scan_result() - orchestration and error handling
# ---------------------------------------------------------------------------

def test_main_saves_and_reports_the_path(capsys, tmp_path):
    path = main.save_scan_result(TARGET, CONFIG, SCAN_RESULT, tmp_path)
    assert path is not None and path.exists()
    assert str(path) in capsys.readouterr().out


def test_main_saves_nothing_without_structured_results(capsys, tmp_path):
    assert main.save_scan_result(TARGET, CONFIG, None, tmp_path) is None
    assert list(tmp_path.iterdir()) == []
    assert "No structured results to save." in capsys.readouterr().out


def test_main_reports_a_failed_save_instead_of_crashing(monkeypatch, capsys, tmp_path):
    def broken_save(record, created_at, results_dir):
        raise PermissionError("Permission denied")

    monkeypatch.setattr(storage, "save_scan_record", broken_save)

    assert main.save_scan_result(TARGET, CONFIG, SCAN_RESULT, tmp_path) is None
    assert "Could not save scan results" in capsys.readouterr().out
