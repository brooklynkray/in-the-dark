import subprocess


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