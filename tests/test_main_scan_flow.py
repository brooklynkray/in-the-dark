"""
Tests for the interactive scan configuration / consent flow in
main.py: ask_technique(), ask_port_scope(), ask_service_detection(),
ask_timing(), get_scan_config_from_user(), and
get_confirmed_scan_config().

input() is monkeypatched to a fixed queue of responses so these run
without a real terminal or human. None of these tests touch Nmap or a
subprocess - they only exercise the guided-question/consent control
flow and assert on the resulting ScanConfig (or None), or on the
preview's printed output for the privilege-warning tests.
"""

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
# ask_technique() / ask_port_scope() / ask_service_detection() / ask_timing()
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


def test_ask_service_detection_accepts_default_on_blank_input(monkeypatch):
    queued_input(monkeypatch, [""])
    assert main.ask_service_detection(True) is True


def test_ask_service_detection_selects_non_default_option(monkeypatch):
    queued_input(monkeypatch, ["n"])
    assert main.ask_service_detection(True) is False


def test_ask_service_detection_rejects_invalid_input_then_accepts(monkeypatch):
    queued_input(monkeypatch, ["maybe", "y"])
    assert main.ask_service_detection(False) is True


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
# get_scan_config_from_user() - composing all four questions, with/without
# a previous ScanConfig supplying the defaults. Questions are asked in
# technique, port scope, service detection, timing order.
# ---------------------------------------------------------------------------

def test_get_scan_config_from_user_defaults_to_scanconfig_defaults(monkeypatch):
    queued_input(monkeypatch, ["", "", "", ""])
    assert main.get_scan_config_from_user() == scan.ScanConfig()


def test_get_scan_config_from_user_uses_previous_config_as_default(monkeypatch):
    previous = scan.ScanConfig(
        technique=scan.Technique.SYN,
        port_scope=scan.PortScope.ALL_TCP,
        service_detection=False,
        timing=scan.Timing.T1,
    )
    # Blank input on all four questions should preserve the previous
    # answers, not fall back to scan.ScanConfig()'s built-in defaults.
    queued_input(monkeypatch, ["", "", "", ""])
    assert main.get_scan_config_from_user(previous) == previous


# ---------------------------------------------------------------------------
# get_confirmed_scan_config() - the full guided/preview/consent loop.
# `elevated` doesn't affect the returned ScanConfig, only what the
# preview prints (covered separately below), so a fixed True is used
# throughout these tests to keep them focused on the config itself.
# ---------------------------------------------------------------------------

def test_accepting_default_configuration(monkeypatch):
    # Technique, port scope, service detection, timing: all blank
    # (default). Consent: "1" (yes).
    queued_input(monkeypatch, ["", "", "", "", "1"])
    assert main.get_confirmed_scan_config(TARGET, elevated=True) == scan.ScanConfig()


def test_selecting_non_default_options_and_accepting(monkeypatch):
    # Technique: "2" (SYN). Port scope: "3" (ALL_TCP). Service
    # detection: "n" (disabled). Timing: "6" (T5). Consent: "y".
    queued_input(monkeypatch, ["2", "3", "n", "6", "y"])
    config = main.get_confirmed_scan_config(TARGET, elevated=True)
    assert config == scan.ScanConfig(
        technique=scan.Technique.SYN,
        port_scope=scan.PortScope.ALL_TCP,
        service_detection=False,
        timing=scan.Timing.T5,
    )


def test_declining_and_reconfiguring_preserves_previous_selection(monkeypatch):
    # Pass 1: SYN, ALL_TCP, service detection off, timing T1, then
    # decline ("2"). Pass 2: accept all four defaults, which must now
    # be the previous answers rather than CONNECT/TOP_1000/enabled/T3.
    # Consent: "1".
    queued_input(monkeypatch, ["2", "3", "n", "2", "2", "", "", "", "", "1"])
    config = main.get_confirmed_scan_config(TARGET, elevated=True)
    assert config == scan.ScanConfig(
        technique=scan.Technique.SYN,
        port_scope=scan.PortScope.ALL_TCP,
        service_detection=False,
        timing=scan.Timing.T1,
    )


def test_declining_and_deliberately_changing_one_answer(monkeypatch):
    # Pass 1: technique/timing default, ALL_TCP, detection enabled
    # (default), then decline ("2"). Pass 2: keep everything else
    # (blank = preserved), but deliberately turn detection off this
    # time. Consent: "1".
    queued_input(monkeypatch, ["", "3", "", "", "2", "", "", "n", "", "1"])
    config = main.get_confirmed_scan_config(TARGET, elevated=True)
    assert config == scan.ScanConfig(
        technique=scan.Technique.CONNECT,
        port_scope=scan.PortScope.ALL_TCP,
        service_detection=False,
        timing=scan.Timing.T3,
    )


def test_invalid_consent_input_is_rejected_then_reprompted(monkeypatch):
    queued_input(monkeypatch, ["", "", "", "", "banana", "1"])
    assert main.get_confirmed_scan_config(TARGET, elevated=True) == scan.ScanConfig()


def test_exiting_at_consent_returns_none(monkeypatch):
    queued_input(monkeypatch, ["", "", "", "", "3"])
    assert main.get_confirmed_scan_config(TARGET, elevated=True) is None


# ---------------------------------------------------------------------------
# display_scan_preview() - the SYN-without-privilege warning
# ---------------------------------------------------------------------------

WARNING_TEXT = "refuse to run a SYN scan"


def test_preview_warns_when_syn_selected_without_privilege(capsys):
    scan_config = scan.ScanConfig(technique=scan.Technique.SYN)
    main.display_scan_preview(TARGET, scan_config, elevated=False)
    output = capsys.readouterr().out
    assert WARNING_TEXT in output


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
