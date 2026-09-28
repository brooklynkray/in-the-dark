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


def test_an_unknown_service_falls_back_to_generic_guidance():
    advice = guidance.guidance_for(TARGET, _port(service="ssh", port=22))
    assert advice is not None
    assert "ssh" in advice.what
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
