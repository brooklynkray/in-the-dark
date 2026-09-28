"""
Tests for environment.py and the startup privilege line in main.py.

The key behaviour pinned down here: environment detection reports
only what it can know for certain - whether this session is running
as root - and never calls sudo. An earlier version ran `sudo -n -v`,
which reported "sudo available" only when sudo credentials happened
to be cached, and as a side effect extended that cached sudo session
every time the tool started.
"""

import environment
import main


class FakeCompletedProcess:
    def __init__(self, stdout):
        self.stdout = stdout
        self.returncode = 0


def fake_subprocess(monkeypatch, uid="1000", user="brooklyn"):
    """
    Replace subprocess.run inside environment.py with a fake that
    answers whoami / id -u, and record every argv it was asked to run.
    """
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        if argv == ["whoami"]:
            return FakeCompletedProcess(f"{user}\n")
        if argv == ["id", "-u"]:
            return FakeCompletedProcess(f"{uid}\n")
        raise AssertionError(f"unexpected command: {argv}")

    monkeypatch.setattr(environment.subprocess, "run", fake_run)
    monkeypatch.setattr(environment.shutil, "which", lambda name: "/usr/bin/nmap")
    return calls


def test_environment_detection_never_calls_sudo(monkeypatch):
    calls = fake_subprocess(monkeypatch)
    environment.get_environment()
    assert calls, "expected whoami / id to be run"
    assert not any("sudo" in argv for argv in calls)


def test_uid_zero_is_reported_as_elevated(monkeypatch):
    fake_subprocess(monkeypatch, uid="0", user="root")
    env = environment.get_environment()
    assert env.elevated is True
    assert env.user == "root"


def test_non_zero_uid_is_reported_as_not_elevated(monkeypatch):
    fake_subprocess(monkeypatch, uid="1000")
    env = environment.get_environment()
    assert env.elevated is False
    assert env.user == "brooklyn"


def run_startup(monkeypatch, capsys, elevated):
    env = environment.EnvironmentInfo(
        user="brooklyn", elevated=elevated, nmap_path="/usr/bin/nmap"
    )
    monkeypatch.setattr(main.environment, "get_environment", lambda: env)
    returned = main.show_startup_sequence()
    return returned, capsys.readouterr().out


def test_startup_reports_unprivileged_session(monkeypatch, capsys):
    returned, output = run_startup(monkeypatch, capsys, elevated=False)
    assert returned is False
    assert "(brooklyn, unprivileged)" in output
    assert "sudo" not in output


def test_startup_reports_elevated_session(monkeypatch, capsys):
    returned, output = run_startup(monkeypatch, capsys, elevated=True)
    assert returned is True
    assert "(brooklyn, elevated)" in output
    assert "sudo" not in output
