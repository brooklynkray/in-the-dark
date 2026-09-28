"""
Tests for guidance.py - the "where to look next" producers.

These pin down the two things that make the guidance trustworthy:
it reacts to what Nmap actually observed (confirmed vs guessed, version
present or not, TLS or not, the port number), and it never claims more
certainty than that evidence supports.
"""

import guidance
import results


TARGET = "10.10.10.5"


def _port(**overrides):
    fields = dict(
        port=80,
        protocol="tcp",
        state="open",
        service="http",
        product=None,
        version=None,
    )
    fields.update(overrides)
    return results.PortResult(**fields)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def test_a_closed_port_gets_no_guidance():
    assert guidance.guidance_for(TARGET, _port(state="closed")) is None


def test_an_unhandled_service_falls_back_to_generic_guidance():
    # telnet has no producer of its own yet, so it must hit the fallback.
    advice = guidance.guidance_for(TARGET, _port(service="telnet", port=23))
    assert advice is not None
    assert "telnet" in advice.what
    assert advice.commands == ()   # generic guidance suggests no tools yet


def test_http_proxy_alias_routes_to_the_http_producer():
    # A guessed "http-proxy" on 8080 must get web guidance, not generic.
    advice = guidance.guidance_for(TARGET, _port(service="http-proxy", port=8080))
    assert "web service" in advice.what


# ---------------------------------------------------------------------------
# HTTP producer
# ---------------------------------------------------------------------------

def test_confirmed_http_suggests_whatweb_and_gobuster_without_a_caution():
    advice = guidance.guidance_for(
        TARGET, _port(product="nginx", version="1.18.0", method="probed")
    )
    tools = [command.tool for command in advice.commands]
    assert "whatweb" in tools
    assert "gobuster" in tools
    assert advice.caution is None


def test_guessed_http_warns_to_confirm_before_trusting_it():
    advice = guidance.guidance_for(TARGET, _port(service="http", method="table"))
    assert advice.caution is not None
    assert "guessed from the port number" in advice.caution


def test_https_uses_the_https_scheme_and_suggests_reading_the_certificate():
    advice = guidance.guidance_for(
        TARGET, _port(port=443, tunnel="ssl", method="probed")
    )
    commands = " ".join(command.command for command in advice.commands)
    assert f"https://{TARGET}" in commands
    assert any(command.tool == "openssl" for command in advice.commands)
    assert any("certificate" in check for check in advice.checks)


def test_http_url_includes_a_non_default_port():
    advice = guidance.guidance_for(TARGET, _port(port=8080, method="probed"))
    commands = " ".join(command.command for command in advice.commands)
    assert f"http://{TARGET}:8080" in commands


def test_web_service_on_a_genuinely_unusual_port_is_flagged():
    # 3000 is not one of the common web ports, so it is worth a mention.
    advice = guidance.guidance_for(TARGET, _port(port=3000, method="probed"))
    assert any("unusual" in note for note in advice.notes)


def test_web_service_on_a_common_alt_port_is_not_flagged_as_unusual():
    # 8080 is a common alternate HTTP port; flagging it would be noise.
    for common in (80, 8080):
        advice = guidance.guidance_for(TARGET, _port(port=common, method="probed"))
        assert not any("unusual" in note for note in advice.notes)


# ---------------------------------------------------------------------------
# The searchsploit lead - a lead to verify, never a claimed vulnerability
# ---------------------------------------------------------------------------

def test_a_version_produces_a_searchsploit_lead_phrased_as_something_to_verify():
    advice = guidance.guidance_for(
        TARGET, _port(product="Apache httpd", version="2.4.41", method="probed")
    )
    lead = " ".join(advice.notes)
    assert "searchsploit Apache httpd 2.4.41" in lead
    assert "verify" in lead
    # It must never assert the target is vulnerable.
    assert "vulnerable" not in lead.lower()


def test_no_version_means_no_searchsploit_lead():
    advice = guidance.guidance_for(TARGET, _port(method="probed"))
    assert not any("searchsploit" in note for note in advice.notes)


# ---------------------------------------------------------------------------
# FTP / SMB / SSH / DNS producers
# ---------------------------------------------------------------------------

def test_ftp_suggests_an_anonymous_login_check():
    advice = guidance.guidance_for(TARGET, _port(service="ftp", port=21))
    assert "anonymous" in " ".join(advice.checks).lower()
    assert any(command.tool == "ftp" for command in advice.commands)


def test_smb_service_names_all_route_to_smb_guidance():
    for name in ("microsoft-ds", "netbios-ssn", "smb"):
        advice = guidance.guidance_for(TARGET, _port(service=name, port=445))
        assert "SMB" in advice.what
        assert any(command.tool == "smbclient" for command in advice.commands)


def test_ssh_advises_against_brute_forcing_first():
    advice = guidance.guidance_for(TARGET, _port(service="ssh", port=22))
    joined = " ".join(advice.checks).lower()
    assert "brute" in joined  # the point is to say: don't, not yet


def test_dns_is_matched_on_nmaps_service_name_domain():
    # Nmap names the DNS service "domain", not "dns".
    advice = guidance.guidance_for(TARGET, _port(service="domain", port=53))
    assert "Domain Name System" in advice.what
    commands = " ".join(command.command for command in advice.commands)
    assert "axfr" in commands


def test_every_new_producer_warns_when_the_service_was_guessed():
    for name, portnum in (("ftp", 21), ("microsoft-ds", 445), ("ssh", 22),
                          ("domain", 53)):
        advice = guidance.guidance_for(
            TARGET, _port(service=name, port=portnum, method="table")
        )
        assert advice.caution is not None
        assert "guessed from the port number" in advice.caution
