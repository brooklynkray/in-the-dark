"""
Tests for the interactive scan configuration / consent flow in
main.py: ask_technique(), ask_port_scope(), ask_service_detection(),
ask_os_detection(), ask_timing(), get_scan_config_from_user(), and
get_confirmed_scan_config() - plus the XML-output temp-file lifecycle
and result-display orchestration (_create_xml_output_path(),
_cleanup_xml_output_path(), run_and_display_scan()).

input() is monkeypatched to a fixed queue of responses so these run
without a real terminal or human. None of these tests touch Nmap or a
subprocess - they only exercise the guided-question/consent control
flow and assert on the resulting ScanConfig (or None), on the
preview's printed output for the privilege-warning tests, or on
run_and_display_scan()'s output with executor.run() mocked out.
"""

import os

import executor
import main
import scan
import target


def queued_input(monkeypatch, responses):
    """
    Replace input() with one that returns each response in order,
    raising a clear assertion error if more input is requested than
    was queued (instead of a confusing StopIteration).
    """

    responses_iter = iter(responses)

    def fake_input(prompt=""):
        try:
            return next(responses_iter)
        except StopIteration:
            raise AssertionError(
                "input() was called more times than test responses were queued"
            )

    monkeypatch.setattr("builtins.input", fake_input)


TARGET = target.TargetInfo(value="10.10.10.5", type="IPv4")


# ---------------------------------------------------------------------------
# ask_technique() / ask_port_scope() / ask_service_detection() /
# ask_os_detection() / ask_timing()
# ---------------------------------------------------------------------------

def test_ask_technique_accepts_default_on_blank_input(monkeypatch):
    queued_input(monkeypatch, [""])
    assert main.ask_technique(scan.Technique.CONNECT) == scan.Technique.CONNECT


def test_ask_technique_selects_non_default_option(monkeypatch):
    queued_input(monkeypatch, ["2"])
    assert main.ask_technique(scan.Technique.CONNECT) == scan.Technique.SYN


def test_ask_technique_rejects_invalid_input_then_accepts(monkeypatch):
    queued_input(monkeypatch, ["banana", "9", "2"])
    assert main.ask_technique(scan.Technique.CONNECT) == scan.Technique.SYN


def test_ask_port_scope_accepts_default_on_blank_input(monkeypatch):
    queued_input(monkeypatch, [""])
    assert main.ask_port_scope(scan.PortScope.TOP_1000) == scan.PortScope.TOP_1000


def test_ask_port_scope_selects_non_default_option(monkeypatch):
    queued_input(monkeypatch, ["3"])
    assert main.ask_port_scope(scan.PortScope.TOP_1000) == scan.PortScope.ALL_TCP


def test_ask_port_scope_rejects_invalid_input_then_accepts(monkeypatch):
    queued_input(monkeypatch, ["banana", "9", "1"])
    assert main.ask_port_scope(scan.PortScope.TOP_1000) == scan.PortScope.COMMON


def test_ask_custom_ports_accepts_valid_input(monkeypatch):
    queued_input(monkeypatch, ["80,443"])
    assert main.ask_custom_ports(None) == "80,443"


def test_ask_custom_ports_rejects_invalid_input_then_accepts(monkeypatch):
    queued_input(monkeypatch, ["not-ports", "80,443"])
    assert main.ask_custom_ports(None) == "80,443"


def test_ask_custom_ports_requires_non_blank_input_when_no_default(monkeypatch):
    # Blank input is treated as an empty (invalid) specification and
    # re-prompted, since there is no previous value to fall back to.
    queued_input(monkeypatch, ["", "80,443"])
    assert main.ask_custom_ports(None) == "80,443"


def test_ask_custom_ports_preserves_previous_value_on_blank_input(monkeypatch):
    queued_input(monkeypatch, [""])
    assert main.ask_custom_ports("80,443") == "80,443"


def test_ask_custom_ports_selects_new_value_over_previous_default(monkeypatch):
    queued_input(monkeypatch, ["1-1024"])
    assert main.ask_custom_ports("80,443") == "1-1024"


def test_ask_service_detection_accepts_default_on_blank_input(monkeypatch):
    queued_input(monkeypatch, [""])
    assert main.ask_service_detection(True) is True


def test_ask_service_detection_selects_non_default_option(monkeypatch):
    queued_input(monkeypatch, ["n"])
    assert main.ask_service_detection(True) is False


def test_ask_service_detection_rejects_invalid_input_then_accepts(monkeypatch):
    queued_input(monkeypatch, ["maybe", "y"])
    assert main.ask_service_detection(False) is True


def test_ask_os_detection_accepts_default_on_blank_input(monkeypatch):
    queued_input(monkeypatch, [""])
    assert main.ask_os_detection(False) is False


def test_ask_os_detection_selects_non_default_option(monkeypatch):
    queued_input(monkeypatch, ["y"])
    assert main.ask_os_detection(False) is True


def test_ask_os_detection_rejects_invalid_input_then_accepts(monkeypatch):
    queued_input(monkeypatch, ["maybe", "y"])
    assert main.ask_os_detection(False) is True


def test_ask_timing_accepts_default_on_blank_input(monkeypatch):
    queued_input(monkeypatch, [""])
    assert main.ask_timing(scan.Timing.T3) == scan.Timing.T3


def test_ask_timing_selects_non_default_option(monkeypatch):
    queued_input(monkeypatch, ["1"])
    assert main.ask_timing(scan.Timing.T3) == scan.Timing.T0


def test_ask_timing_rejects_invalid_input_then_accepts(monkeypatch):
    queued_input(monkeypatch, ["banana", "9", "6"])
    assert main.ask_timing(scan.Timing.T3) == scan.Timing.T5


# ---------------------------------------------------------------------------
# get_scan_config_from_user() - composing all five questions, with/without
# a previous ScanConfig supplying the defaults. Questions are asked in
# technique, port scope, service detection, OS detection, timing order.
# ---------------------------------------------------------------------------

def test_get_scan_config_from_user_defaults_to_scanconfig_defaults(monkeypatch):
    queued_input(monkeypatch, ["", "", "", "", ""])
    assert main.get_scan_config_from_user() == scan.ScanConfig()


def test_get_scan_config_from_user_uses_previous_config_as_default(monkeypatch):
    previous = scan.ScanConfig(
        technique=scan.Technique.SYN,
        port_scope=scan.PortScope.ALL_TCP,
        service_detection=False,
        os_detection=True,
        timing=scan.Timing.T1,
    )
    # Blank input on all five questions should preserve the previous
    # answers, not fall back to scan.ScanConfig()'s built-in defaults.
    queued_input(monkeypatch, ["", "", "", "", ""])
    assert main.get_scan_config_from_user(previous) == previous


def test_get_scan_config_from_user_with_custom_port_scope(monkeypatch):
    # Technique blank, port scope "4" (CUSTOM) triggers the follow-up
    # question, then service detection/OS detection/timing blank.
    queued_input(monkeypatch, ["", "4", "80,443", "", "", ""])
    config = main.get_scan_config_from_user()
    assert config.port_scope == scan.PortScope.CUSTOM
    assert config.custom_ports == "80,443"


def test_get_scan_config_from_user_leaves_custom_ports_none_for_other_scopes(
    monkeypatch,
):
    # Port scope "3" (ALL_TCP) never triggers the custom-ports
    # question, so no extra input is queued for it.
    queued_input(monkeypatch, ["", "3", "", "", ""])
    config = main.get_scan_config_from_user()
    assert config.port_scope == scan.PortScope.ALL_TCP
    assert config.custom_ports is None


# ---------------------------------------------------------------------------
# get_confirmed_scan_config() - the full guided/preview/consent loop.
# `elevated` doesn't affect the returned ScanConfig, only what the
# preview prints (covered separately below), so a fixed True is used
# throughout these tests to keep them focused on the config itself.
# ---------------------------------------------------------------------------

def test_accepting_default_configuration(monkeypatch):
    # Technique, port scope, service detection, OS detection, timing:
    # all blank (default). Consent: "1" (yes).
    queued_input(monkeypatch, ["", "", "", "", "", "1"])
    assert main.get_confirmed_scan_config(TARGET, elevated=True) == scan.ScanConfig()


def test_selecting_non_default_options_and_accepting(monkeypatch):
    # Technique: "2" (SYN). Port scope: "3" (ALL_TCP). Service
    # detection: "n" (disabled). OS detection: "y" (enabled). Timing:
    # "6" (T5). Consent: "y".
    queued_input(monkeypatch, ["2", "3", "n", "y", "6", "y"])
    config = main.get_confirmed_scan_config(TARGET, elevated=True)
    assert config == scan.ScanConfig(
        technique=scan.Technique.SYN,
        port_scope=scan.PortScope.ALL_TCP,
        service_detection=False,
        os_detection=True,
        timing=scan.Timing.T5,
    )


def test_declining_and_reconfiguring_preserves_previous_selection(monkeypatch):
    # Pass 1: SYN, ALL_TCP, service detection off, OS detection on,
    # timing T1, then decline ("2"). Pass 2: accept all five defaults,
    # which must now be the previous answers rather than
    # CONNECT/TOP_1000/enabled/disabled/T3. Consent: "1".
    queued_input(
        monkeypatch,
        ["2", "3", "n", "y", "2", "2", "", "", "", "", "", "1"],
    )
    config = main.get_confirmed_scan_config(TARGET, elevated=True)
    assert config == scan.ScanConfig(
        technique=scan.Technique.SYN,
        port_scope=scan.PortScope.ALL_TCP,
        service_detection=False,
        os_detection=True,
        timing=scan.Timing.T1,
    )


def test_declining_and_deliberately_changing_one_answer(monkeypatch):
    # Pass 1: technique/timing default, ALL_TCP, detection enabled
    # (default), OS detection off (default), then decline ("2").
    # Pass 2: keep everything else (blank = preserved), but
    # deliberately turn service detection off this time. Consent: "1".
    queued_input(
        monkeypatch,
        ["", "3", "", "", "", "2", "", "", "n", "", "", "1"],
    )
    config = main.get_confirmed_scan_config(TARGET, elevated=True)
    assert config == scan.ScanConfig(
        technique=scan.Technique.CONNECT,
        port_scope=scan.PortScope.ALL_TCP,
        service_detection=False,
        os_detection=False,
        timing=scan.Timing.T3,
    )


def test_selecting_custom_ports_and_accepting(monkeypatch):
    # Port scope: "4" (CUSTOM). Custom ports: "1-1024,3389". Everything
    # else blank/default. Consent: "1".
    queued_input(monkeypatch, ["", "4", "1-1024,3389", "", "", "", "1"])
    config = main.get_confirmed_scan_config(TARGET, elevated=True)
    assert config == scan.ScanConfig(
        port_scope=scan.PortScope.CUSTOM,
        custom_ports="1-1024,3389",
    )


def test_declining_and_reconfiguring_preserves_custom_ports(monkeypatch):
    # Pass 1: CUSTOM with "80,443", then decline ("2"). Pass 2: accept
    # every default, including the preserved custom ports value via
    # blank input (port scope defaults back to CUSTOM too, which
    # re-triggers the custom-ports question). Consent: "1".
    queued_input(
        monkeypatch,
        [
            "", "4", "80,443", "", "", "", "2",   # pass 1 (7 answers)
            "", "", "", "", "", "", "1",           # pass 2 (7 answers)
        ],
    )
    config = main.get_confirmed_scan_config(TARGET, elevated=True)
    assert config == scan.ScanConfig(
        port_scope=scan.PortScope.CUSTOM,
        custom_ports="80,443",
    )


def test_declining_and_switching_away_from_custom_resets_custom_ports(monkeypatch):
    # Pass 1: CUSTOM with "80,443", then decline ("2"). Pass 2: switch
    # to TOP_1000 ("2") instead - custom_ports must revert to None,
    # not linger from pass 1's answer. Consent: "1".
    queued_input(
        monkeypatch,
        [
            "", "4", "80,443", "", "", "", "2",  # pass 1 (7 answers)
            "", "2", "", "", "", "1",             # pass 2 (6 answers)
        ],
    )
    config = main.get_confirmed_scan_config(TARGET, elevated=True)
    assert config.port_scope == scan.PortScope.TOP_1000
    assert config.custom_ports is None


def test_invalid_consent_input_is_rejected_then_reprompted(monkeypatch):
    queued_input(monkeypatch, ["", "", "", "", "", "banana", "1"])
    assert main.get_confirmed_scan_config(TARGET, elevated=True) == scan.ScanConfig()


def test_exiting_at_consent_returns_none(monkeypatch):
    queued_input(monkeypatch, ["", "", "", "", "", "3"])
    assert main.get_confirmed_scan_config(TARGET, elevated=True) is None


# ---------------------------------------------------------------------------
# display_scan_preview() - the privileged-capability warning
# ---------------------------------------------------------------------------

WARNING_TEXT = "refuse to run"
SYN_ONLY_WARNING = "requires elevated privileges for SYN scanning, so Nmap will likely refuse to run it"
OS_ONLY_WARNING = "requires elevated privileges for OS detection, so Nmap will likely refuse to run it"
COMBINED_WARNING = (
    "requires elevated privileges for SYN scanning and OS detection, "
    "so Nmap will likely refuse to run it"
)


def test_preview_warns_when_syn_selected_without_privilege(capsys):
    scan_config = scan.ScanConfig(technique=scan.Technique.SYN)
    main.display_scan_preview(TARGET, scan_config, elevated=False)
    output = capsys.readouterr().out
    assert SYN_ONLY_WARNING in output


def test_preview_does_not_warn_when_syn_selected_with_privilege(capsys):
    scan_config = scan.ScanConfig(technique=scan.Technique.SYN)
    main.display_scan_preview(TARGET, scan_config, elevated=True)
    output = capsys.readouterr().out
    assert WARNING_TEXT not in output


def test_preview_does_not_warn_for_connect_regardless_of_privilege(capsys):
    scan_config = scan.ScanConfig(technique=scan.Technique.CONNECT)
    main.display_scan_preview(TARGET, scan_config, elevated=False)
    output = capsys.readouterr().out
    assert WARNING_TEXT not in output


def test_preview_warns_when_os_detection_selected_without_privilege(capsys):
    scan_config = scan.ScanConfig(os_detection=True)
    main.display_scan_preview(TARGET, scan_config, elevated=False)
    output = capsys.readouterr().out
    assert OS_ONLY_WARNING in output


def test_preview_does_not_warn_when_os_detection_selected_with_privilege(capsys):
    scan_config = scan.ScanConfig(os_detection=True)
    main.display_scan_preview(TARGET, scan_config, elevated=True)
    output = capsys.readouterr().out
    assert WARNING_TEXT not in output


def test_preview_does_not_warn_when_os_detection_disabled_and_unprivileged(capsys):
    scan_config = scan.ScanConfig(os_detection=False)
    main.display_scan_preview(TARGET, scan_config, elevated=False)
    output = capsys.readouterr().out
    assert WARNING_TEXT not in output


def test_preview_shows_one_consolidated_warning_for_syn_and_os_detection(capsys):
    scan_config = scan.ScanConfig(
        technique=scan.Technique.SYN, os_detection=True
    )
    main.display_scan_preview(TARGET, scan_config, elevated=False)
    output = capsys.readouterr().out

    # Both capabilities are named together in one warning line...
    assert COMBINED_WARNING in output

    # ...not two separate "refuse to run" paragraphs stacked up.
    assert output.count(WARNING_TEXT) == 1


def test_privilege_warning_does_not_change_the_built_argv(capsys):
    # The warning is purely informational - it must never alter what
    # build_argv() produces for the same ScanConfig.
    scan_config = scan.ScanConfig(
        technique=scan.Technique.SYN, service_detection=False
    )

    main.display_scan_preview(TARGET, scan_config, elevated=False)
    argv_unprivileged = scan.build_argv(TARGET, scan_config)

    main.display_scan_preview(TARGET, scan_config, elevated=True)
    argv_privileged = scan.build_argv(TARGET, scan_config)

    assert argv_unprivileged == argv_privileged == ["nmap", "-sS", "10.10.10.5"]


def test_combined_privilege_warning_does_not_change_the_built_argv(capsys):
    # Same guarantee, but for the combined SYN + OS detection case
    # that triggers the consolidated warning.
    scan_config = scan.ScanConfig(
        technique=scan.Technique.SYN,
        service_detection=False,
        os_detection=True,
    )

    main.display_scan_preview(TARGET, scan_config, elevated=False)
    argv_unprivileged = scan.build_argv(TARGET, scan_config)

    main.display_scan_preview(TARGET, scan_config, elevated=True)
    argv_privileged = scan.build_argv(TARGET, scan_config)

    assert (
        argv_unprivileged
        == argv_privileged
        == ["nmap", "-sS", "-O", "10.10.10.5"]
    )


# ---------------------------------------------------------------------------
# get_confirmed_scan_config() - threading xml_output_path through
# ---------------------------------------------------------------------------

def test_get_confirmed_scan_config_stamps_xml_output_path_onto_result(
    monkeypatch,
):
    queued_input(monkeypatch, ["", "", "", "", "", "1"])
    config = main.get_confirmed_scan_config(
        TARGET, elevated=True, xml_output_path="/tmp/scan.xml"
    )
    assert config.xml_output_path == "/tmp/scan.xml"


def test_get_confirmed_scan_config_without_xml_output_path_leaves_it_none(
    monkeypatch,
):
    # Existing calls that don't pass xml_output_path (the default)
    # must keep working exactly as before this increment.
    queued_input(monkeypatch, ["", "", "", "", "", "1"])
    config = main.get_confirmed_scan_config(TARGET, elevated=True)
    assert config.xml_output_path is None


# ---------------------------------------------------------------------------
# display_scan_preview() - the -oX annotation
# ---------------------------------------------------------------------------

def test_preview_annotates_xml_output_path_as_tool_managed(capsys):
    scan_config = scan.ScanConfig(xml_output_path="/tmp/scan.xml")
    main.display_scan_preview(TARGET, scan_config, elevated=True)
    output = capsys.readouterr().out
    assert "/tmp/scan.xml" in output
    assert "not a scan setting you chose" in output


def test_preview_has_no_annotation_when_xml_output_path_is_none(capsys):
    scan_config = scan.ScanConfig(xml_output_path=None)
    main.display_scan_preview(TARGET, scan_config, elevated=True)
    output = capsys.readouterr().out
    assert "not a scan setting you chose" not in output


# ---------------------------------------------------------------------------
# Temp-file lifecycle: _create_xml_output_path() / _cleanup_xml_output_path()
# ---------------------------------------------------------------------------

def test_create_xml_output_path_creates_a_real_empty_file():
    path = main._create_xml_output_path()
    try:
        assert os.path.exists(path)
        assert path.endswith(".xml")
        assert os.path.getsize(path) == 0
    finally:
        main._cleanup_xml_output_path(path)


def test_create_xml_output_path_returns_a_unique_path_each_time():
    path_one = main._create_xml_output_path()
    path_two = main._create_xml_output_path()
    try:
        assert path_one != path_two
    finally:
        main._cleanup_xml_output_path(path_one)
        main._cleanup_xml_output_path(path_two)


def test_cleanup_xml_output_path_removes_the_file():
    path = main._create_xml_output_path()
    assert os.path.exists(path)
    main._cleanup_xml_output_path(path)
    assert not os.path.exists(path)


def test_cleanup_xml_output_path_does_not_raise_if_already_removed():
    path = main._create_xml_output_path()
    os.remove(path)
    main._cleanup_xml_output_path(path)  # must not raise


# ---------------------------------------------------------------------------
# run_and_display_scan() - orchestration, with executor.run() mocked out.
# This is the first place in the project that mocks executor.run() itself
# rather than letting it run for real (test_executor.py already covers
# executor.py's own behaviour against real, harmless local processes).
# ---------------------------------------------------------------------------

def _fake_execution_result(stdout="", stderr=""):
    return executor.ExecutionResult(
        return_code=0,
        stdout=stdout,
        stderr=stderr,
        timed_out=False,
        executable_not_found=False,
    )


NORMAL_SCAN_XML = (
    '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
    '<ports><port protocol="tcp" portid="22"><state state="open"/>'
    '<service name="ssh" product="OpenSSH" version="8.2"/>'
    "</port></ports></host></nmaprun>"
)


def test_run_and_display_scan_shows_both_raw_and_structured_output(
    monkeypatch, capsys, tmp_path
):
    xml_path = tmp_path / "scan.xml"
    xml_path.write_text(NORMAL_SCAN_XML, encoding="utf-8")

    monkeypatch.setattr(
        main.executor, "run",
        lambda argv: _fake_execution_result(stdout="Nmap scan report..."),
    )

    scan_config = scan.ScanConfig(xml_output_path=str(xml_path))
    main.run_and_display_scan(TARGET, scan_config)

    output = capsys.readouterr().out
    assert "Nmap scan report..." in output       # raw output still shown
    assert "Scan results" in output               # structured summary added
    assert "22/tcp open ssh (OpenSSH 8.2)" in output


def test_run_and_display_scan_skips_structured_display_when_xml_missing(
    monkeypatch, capsys, tmp_path
):
    xml_path = tmp_path / "never-created.xml"  # Nmap "never ran"

    monkeypatch.setattr(
        main.executor, "run",
        lambda argv: _fake_execution_result(stdout="raw output only"),
    )

    scan_config = scan.ScanConfig(xml_output_path=str(xml_path))
    main.run_and_display_scan(TARGET, scan_config)

    output = capsys.readouterr().out
    assert "raw output only" in output
    assert "Scan results" not in output


def test_run_and_display_scan_skips_structured_display_when_xml_empty(
    monkeypatch, capsys, tmp_path
):
    # The realistic "executable not found" case: _create_xml_output_path()
    # creates an empty file, but Nmap never runs, so it stays empty.
    xml_path = tmp_path / "empty.xml"
    xml_path.write_text("", encoding="utf-8")

    monkeypatch.setattr(
        main.executor, "run",
        lambda argv: executor.ExecutionResult(
            return_code=None, stdout="", stderr="",
            timed_out=False, executable_not_found=True,
        ),
    )

    scan_config = scan.ScanConfig(xml_output_path=str(xml_path))
    main.run_and_display_scan(TARGET, scan_config)

    output = capsys.readouterr().out
    assert "could not be started" in output
    assert "Scan results" not in output


def test_run_and_display_scan_uses_the_same_argv_that_was_previewed(
    monkeypatch, tmp_path
):
    # The exact argv passed to executor.run() must be scan.build_argv()'s
    # output for scan_config - never rebuilt, never a different list.
    captured = {}

    def fake_run(argv):
        captured["argv"] = argv
        return _fake_execution_result()

    monkeypatch.setattr(main.executor, "run", fake_run)

    xml_path = tmp_path / "scan.xml"
    scan_config = scan.ScanConfig(
        technique=scan.Technique.SYN, xml_output_path=str(xml_path)
    )
    main.run_and_display_scan(TARGET, scan_config)

    assert captured["argv"] == scan.build_argv(TARGET, scan_config)
