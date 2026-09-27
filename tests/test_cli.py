"""
Tests for cli.py's startup banner.

These pin down behaviour rather than looks: the banner fits a
standard terminal, the text is identical with or without colour,
and colour codes only appear when colour is enabled.
"""

import re

import cli

ANSI_ESCAPE = re.compile(r"\033\[[0-9;]*m")


def render_banner(capsys, monkeypatch, colour, term="xterm-256color", colorterm=""):
    monkeypatch.setattr(cli, "_COLOUR", colour)
    monkeypatch.setenv("TERM", term)
    monkeypatch.setenv("COLORTERM", colorterm)
    cli.banner()
    return capsys.readouterr().out


def test_logo_rows_are_all_the_same_width():
    widths = {len(line) for line in cli.LOGO_LINES}
    assert len(widths) == 1


def test_there_is_one_shade_per_logo_row_fading_darker():
    assert len(cli._LOGO_ROW_SHADES) == len(cli.LOGO_LINES)
    assert list(cli._LOGO_ROW_SHADES) == sorted(cli._LOGO_ROW_SHADES, reverse=True)


def test_banner_fits_an_80_column_terminal(capsys, monkeypatch):
    output = render_banner(capsys, monkeypatch, colour=True)
    visible = ANSI_ESCAPE.sub("", output)
    assert max(len(line) for line in visible.splitlines()) <= 80


def test_banner_without_colour_has_no_escape_codes(capsys, monkeypatch):
    output = render_banner(capsys, monkeypatch, colour=False)
    assert "\033[" not in output
    assert "I N   T H E" in output
    assert cli.LOGO_LINES[0].rstrip() in output
    assert "GUIDED SECURITY RECONNAISSANCE" in output


def test_colour_changes_only_the_codes_never_the_text(capsys, monkeypatch):
    plain = render_banner(capsys, monkeypatch, colour=False)
    coloured = render_banner(capsys, monkeypatch, colour=True)
    assert "\033[38;5;" in coloured
    assert ANSI_ESCAPE.sub("", coloured) == plain


def test_terminal_without_256_colours_gets_the_simple_fallback(capsys, monkeypatch):
    plain = render_banner(capsys, monkeypatch, colour=False)
    fallback = render_banner(capsys, monkeypatch, colour=True, term="xterm")
    assert "\033[38;5;" not in fallback
    assert "\033[1m" in fallback  # bold top half
    assert "\033[2m" in fallback  # dim bottom half
    assert ANSI_ESCAPE.sub("", fallback) == plain


def test_truecolor_terminal_counts_as_256_colour_capable(capsys, monkeypatch):
    output = render_banner(
        capsys, monkeypatch, colour=True, term="xterm", colorterm="truecolor"
    )
    assert "\033[38;5;" in output
