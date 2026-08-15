import subprocess
import shutil
from dataclasses import dataclass


@dataclass
class EnvironmentInfo:
    user: str
    elevated: bool
    nmap_path: str | None
    sudo_available: bool


def get_current_user():
    result = subprocess.run(
        ["whoami"],
        capture_output=True,
        text=True
    )

    return result.stdout.strip()


def is_root():
    result = subprocess.run(
        ["id", "-u"],
        capture_output=True,
        text=True
    )

    return result.stdout.strip() == "0"


def get_nmap_path():
    return shutil.which("nmap")


def is_sudo_available():
    try:
        result = subprocess.run(
            ["sudo", "-n", "-v"],
            capture_output=True,
            text=True
        )
    except FileNotFoundError:
        # sudo isn't installed on this system at all, so it can't be
        # available for use. Some minimal environments don't ship it.
        return False

    return result.returncode == 0


def get_environment():
    return EnvironmentInfo(
        user=get_current_user(),
        elevated=is_root(),
        nmap_path=get_nmap_path(),
        sudo_available=is_sudo_available()
    )