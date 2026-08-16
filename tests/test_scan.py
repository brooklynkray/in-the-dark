"""
Tests for scan.py - ScanConfig, build_argv(), and the flag/metadata
agreement between them.

These only exercise pure functions and never invoke Nmap: they check
what argv build_argv() *would* produce, not what running it does.
"""

import dataclasses

import pytest

import scan
import target


def make_target(value, target_type="IPv4"):
    return target.TargetInfo(value=value, type=target_type)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

def test_default_scan_config_is_top_1000_with_service_detection():
    config = scan.ScanConfig()
    assert config.port_scope == scan.PortScope.TOP_1000
    assert config.service_detection is True
    assert config.timing == scan.Timing.T3
    assert config.technique == scan.Technique.CONNECT
    assert config.os_detection is False
    assert config.custom_ports is None


def test_scan_config_is_frozen():
    config = scan.ScanConfig()
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.port_scope = scan.PortScope.ALL_TCP


# ---------------------------------------------------------------------------
# Port scope (requirements 1-3)
# ---------------------------------------------------------------------------

def test_common_port_scope_emits_dash_F():
    config = scan.ScanConfig(port_scope=scan.PortScope.COMMON, service_detection=False)
    argv = scan.build_argv(make_target("10.10.10.5"), config)
    assert "-F" in argv


def test_top_1000_emits_no_explicit_port_flag():
    config = scan.ScanConfig(port_scope=scan.PortScope.TOP_1000, service_detection=False)
    argv = scan.build_argv(make_target("10.10.10.5"), config)
    assert "-F" not in argv
    assert "-p-" not in argv


def test_all_tcp_emits_dash_p_dash():
    config = scan.ScanConfig(port_scope=scan.PortScope.ALL_TCP, service_detection=False)
    argv = scan.build_argv(make_target("10.10.10.5"), config)
    assert "-p-" in argv


# ---------------------------------------------------------------------------
# Custom ports
# ---------------------------------------------------------------------------

def test_custom_ports_emits_dash_p_with_value():
    config = scan.ScanConfig(
        port_scope=scan.PortScope.CUSTOM, custom_ports="80,443"
    )
    argv = scan.build_argv(make_target("10.10.10.5"), config)
    assert "-p" in argv
    assert "80,443" in argv


def test_custom_ports_flag_and_value_sit_in_port_scope_position():
    config = scan.ScanConfig(
        port_scope=scan.PortScope.CUSTOM,
        custom_ports="80,443",
        service_detection=True,
        timing=scan.Timing.T4,
    )
    argv = scan.build_argv(make_target("10.10.10.5"), config)
    assert argv == ["nmap", "-sT", "-p", "80,443", "-sV", "-T4", "10.10.10.5"]


def test_custom_ports_value_is_its_own_element_not_fused_with_flag():
    config = scan.ScanConfig(
        port_scope=scan.PortScope.CUSTOM, custom_ports="80,443"
    )
    argv = scan.build_argv(make_target("10.10.10.5"), config)

    # "-p" and the value are two distinct elements - never "-p80,443".
    assert argv.count("-p") == 1
    assert "-p80,443" not in argv
    assert argv[argv.index("-p") + 1] == "80,443"


@pytest.mark.parametrize("hostile_value", [
    "80;rm -rf /",
    "80 && whoami",
    "80 -oN pwned.txt",
    "$(whoami)",
    "`whoami`",
    "--script=malicious",
])
def test_hostile_custom_ports_value_is_never_split_or_concatenated(hostile_value):
    # Defense in depth: build_argv() must keep custom_ports as one
    # argv element even if something upstream failed to validate it -
    # independent of ports.parse_custom_ports()'s own protections.
    config = scan.ScanConfig(
        port_scope=scan.PortScope.CUSTOM, custom_ports=hostile_value
    )
    argv = scan.build_argv(make_target("10.10.10.5"), config)

    assert argv.count(hostile_value) == 1
    for element in argv:
        if element != hostile_value:
            assert hostile_value not in element


def test_custom_port_scope_with_none_raises_value_error():
    # CUSTOM + custom_ports=None should be unreachable via the guided
    # flow - this is an internal invariant violation, not something
    # build_argv() should silently paper over.
    config = scan.ScanConfig(port_scope=scan.PortScope.CUSTOM, custom_ports=None)
    with pytest.raises(ValueError):
        scan.build_argv(make_target("10.10.10.5"), config)


def test_advertised_custom_ports_flag_matches_emitted_flag():
    advertised_flag = scan.PORT_SCOPE_INFO[scan.PortScope.CUSTOM].flag
    config = scan.ScanConfig(
        port_scope=scan.PortScope.CUSTOM, custom_ports="80,443"
    )
    argv = scan.build_argv(make_target("10.10.10.5"), config)
    assert advertised_flag in argv


# ---------------------------------------------------------------------------
# Service detection (requirements 4-5)
# ---------------------------------------------------------------------------

def test_service_detection_true_emits_dash_sV():
    config = scan.ScanConfig(port_scope=scan.PortScope.TOP_1000, service_detection=True)
    argv = scan.build_argv(make_target("10.10.10.5"), config)
    assert "-sV" in argv


def test_service_detection_false_emits_no_dash_sV():
    config = scan.ScanConfig(port_scope=scan.PortScope.TOP_1000, service_detection=False)
    argv = scan.build_argv(make_target("10.10.10.5"), config)
    assert "-sV" not in argv


# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

def test_os_detection_true_emits_dash_O():
    config = scan.ScanConfig(os_detection=True)
    argv = scan.build_argv(make_target("10.10.10.5"), config)
    assert "-O" in argv


def test_os_detection_false_emits_no_dash_O():
    config = scan.ScanConfig(os_detection=False)
    argv = scan.build_argv(make_target("10.10.10.5"), config)
    assert "-O" not in argv


def test_os_detection_flag_sits_after_service_detection_and_before_timing():
    config = scan.ScanConfig(
        service_detection=True, os_detection=True, timing=scan.Timing.T4
    )
    argv = scan.build_argv(make_target("10.10.10.5"), config)
    assert argv == ["nmap", "-sT", "-sV", "-O", "-T4", "10.10.10.5"]


# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("timing,flag", [
    (scan.Timing.T0, "-T0"),
    (scan.Timing.T1, "-T1"),
    (scan.Timing.T2, "-T2"),
    (scan.Timing.T4, "-T4"),
    (scan.Timing.T5, "-T5"),
])
def test_non_default_timing_emits_its_flag(timing, flag):
    config = scan.ScanConfig(timing=timing)
    argv = scan.build_argv(make_target("10.10.10.5"), config)
    assert flag in argv


def test_t3_emits_no_explicit_timing_flag():
    config = scan.ScanConfig(timing=scan.Timing.T3)
    argv = scan.build_argv(make_target("10.10.10.5"), config)
    assert not any(flag.startswith("-T") for flag in argv)


@pytest.mark.parametrize("timing,expected", [
    (scan.Timing.T0, ["nmap", "-sT", "-p-", "-sV", "-T0", "10.10.10.5"]),
    (scan.Timing.T3, ["nmap", "-sT", "-p-", "-sV", "10.10.10.5"]),
    (scan.Timing.T5, ["nmap", "-sT", "-p-", "-sV", "-T5", "10.10.10.5"]),
])
def test_timing_flag_sits_after_service_detection_and_before_target(
    timing, expected
):
    config = scan.ScanConfig(
        port_scope=scan.PortScope.ALL_TCP,
        service_detection=True,
        timing=timing,
    )
    assert scan.build_argv(make_target("10.10.10.5"), config) == expected


# ---------------------------------------------------------------------------
# Technique
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("technique,flag", [
    (scan.Technique.CONNECT, "-sT"),
    (scan.Technique.SYN, "-sS"),
])
def test_technique_emits_its_flag(technique, flag):
    config = scan.ScanConfig(technique=technique)
    argv = scan.build_argv(make_target("10.10.10.5"), config)
    assert flag in argv


@pytest.mark.parametrize("technique", list(scan.Technique))
def test_technique_always_emits_an_explicit_flag(technique):
    # Unlike port scope and timing, technique has no "Nmap default"
    # that can be represented by omitting a flag - both members must
    # always produce one.
    config = scan.ScanConfig(technique=technique)
    argv = scan.build_argv(make_target("10.10.10.5"), config)
    assert any(element in ("-sT", "-sS") for element in argv)


def test_technique_flag_sits_immediately_after_nmap():
    config = scan.ScanConfig(
        technique=scan.Technique.SYN,
        port_scope=scan.PortScope.ALL_TCP,
        service_detection=True,
        timing=scan.Timing.T4,
    )
    argv = scan.build_argv(make_target("10.10.10.5"), config)
    assert argv == ["nmap", "-sS", "-p-", "-sV", "-T4", "10.10.10.5"]


# ---------------------------------------------------------------------------
# Combinations (requirement 6) and canonical ordering
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("port_scope,service_detection,expected", [
    (scan.PortScope.COMMON, True, ["nmap", "-sT", "-F", "-sV", "10.10.10.5"]),
    (scan.PortScope.COMMON, False, ["nmap", "-sT", "-F", "10.10.10.5"]),
    (scan.PortScope.TOP_1000, True, ["nmap", "-sT", "-sV", "10.10.10.5"]),
    (scan.PortScope.TOP_1000, False, ["nmap", "-sT", "10.10.10.5"]),
    (scan.PortScope.ALL_TCP, True, ["nmap", "-sT", "-p-", "-sV", "10.10.10.5"]),
    (scan.PortScope.ALL_TCP, False, ["nmap", "-sT", "-p-", "10.10.10.5"]),
])
def test_port_scope_and_service_detection_combinations(
    port_scope, service_detection, expected
):
    config = scan.ScanConfig(
        port_scope=port_scope, service_detection=service_detection
    )
    assert scan.build_argv(make_target("10.10.10.5"), config) == expected


# ---------------------------------------------------------------------------
# Target placement and integrity (requirements 7-9)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("port_scope", list(scan.PortScope))
@pytest.mark.parametrize("service_detection", [True, False])
@pytest.mark.parametrize("timing", list(scan.Timing))
@pytest.mark.parametrize("technique", list(scan.Technique))
@pytest.mark.parametrize("os_detection", [True, False])
def test_target_is_always_the_final_argv_element(
    port_scope, service_detection, timing, technique, os_detection
):
    # CUSTOM needs a companion value to be a valid ScanConfig at all -
    # None is the unreachable invariant-violation case tested
    # separately in test_custom_port_scope_with_none_raises_value_error.
    custom_ports = "80,443" if port_scope == scan.PortScope.CUSTOM else None

    config = scan.ScanConfig(
        port_scope=port_scope,
        custom_ports=custom_ports,
        service_detection=service_detection,
        timing=timing,
        technique=technique,
        os_detection=os_detection,
    )
    argv = scan.build_argv(make_target("example.com", "hostname"), config)
    assert argv[-1] == "example.com"


@pytest.mark.parametrize("hostile_value", [
    "10.10.10.5; rm -rf /",
    "10.10.10.5 && whoami",
    "10.10.10.5 -oN pwned.txt",
    "$(whoami)",
    "`whoami`",
    "10.10.10.5 -- -p 1-65535",
    "--script=malicious",
])
def test_hostile_target_value_is_never_split_or_concatenated(hostile_value):
    config = scan.ScanConfig()
    argv = scan.build_argv(make_target(hostile_value), config)

    # The hostile string arrives, and leaves, as a single argv element -
    # never split on whitespace, never merged with a neighbouring flag.
    assert argv[-1] == hostile_value
    assert argv.count(hostile_value) == 1

    # No other element absorbed part of the hostile value.
    for element in argv[:-1]:
        assert hostile_value not in element


# ---------------------------------------------------------------------------
# Metadata / build_argv agreement (requirement 10)
# ---------------------------------------------------------------------------

# CUSTOM is excluded here and covered by its own dedicated
# test_advertised_custom_ports_flag_matches_emitted_flag below - it
# needs a companion custom_ports value to be a valid ScanConfig at
# all, unlike the other three (parameter-free) port scopes.
@pytest.mark.parametrize(
    "port_scope",
    [scope for scope in scan.PortScope if scope != scan.PortScope.CUSTOM],
)
def test_advertised_port_scope_flag_matches_emitted_flag(port_scope):
    advertised_flag = scan.PORT_SCOPE_INFO[port_scope].flag

    config = scan.ScanConfig(port_scope=port_scope, service_detection=False)
    argv = scan.build_argv(make_target("10.10.10.5"), config)

    if advertised_flag:
        assert advertised_flag in argv
    else:
        # TOP_1000 advertises no flag, so none should be emitted either.
        assert "-F" not in argv
        assert "-p-" not in argv


def test_advertised_service_detection_flag_matches_emitted_flag():
    advertised_flag = scan.SERVICE_DETECTION_INFO.flag

    enabled_argv = scan.build_argv(
        make_target("10.10.10.5"), scan.ScanConfig(service_detection=True)
    )
    disabled_argv = scan.build_argv(
        make_target("10.10.10.5"), scan.ScanConfig(service_detection=False)
    )

    assert advertised_flag in enabled_argv
    assert advertised_flag not in disabled_argv


@pytest.mark.parametrize("timing", list(scan.Timing))
def test_advertised_timing_flag_matches_emitted_flag(timing):
    advertised_flag = scan.TIMING_INFO[timing].flag

    argv = scan.build_argv(
        make_target("10.10.10.5"), scan.ScanConfig(timing=timing)
    )

    if advertised_flag:
        assert advertised_flag in argv
    else:
        # T3 advertises no flag, so no -T flag at all should be emitted.
        assert not any(element.startswith("-T") for element in argv)


@pytest.mark.parametrize("technique", list(scan.Technique))
def test_advertised_technique_flag_matches_emitted_flag(technique):
    advertised_flag = scan.TECHNIQUE_INFO[technique].flag

    argv = scan.build_argv(
        make_target("10.10.10.5"), scan.ScanConfig(technique=technique)
    )

    # Technique has no "no flag" case - both members always advertise
    # and emit an explicit flag.
    assert advertised_flag
    assert advertised_flag in argv


def test_advertised_os_detection_flag_matches_emitted_flag():
    advertised_flag = scan.OS_DETECTION_INFO.flag

    enabled_argv = scan.build_argv(
        make_target("10.10.10.5"), scan.ScanConfig(os_detection=True)
    )
    disabled_argv = scan.build_argv(
        make_target("10.10.10.5"), scan.ScanConfig(os_detection=False)
    )

    assert advertised_flag in enabled_argv
    assert advertised_flag not in disabled_argv
