import ipaddress
import re


def is_valid_hostname(hostname):
    if len(hostname) > 253:
        return False

    if hostname.endswith("."):
        hostname = hostname[:-1]

    labels = hostname.split(".")

    for label in labels:
        if not label:
            return False

        if len(label) > 63:
            return False

        if not re.fullmatch(r"[A-Za-z0-9-]+", label):
            return False

        if label.startswith("-") or label.endswith("-"):
            return False

    return True


def identify_target(target):
    target = target.strip()

    try:
        ip = ipaddress.ip_address(target)

        if ip.version == 4:
            return "IPv4"

        return "IPv6"

    except ValueError:
        pass

    if re.fullmatch(r"\d+(?:\.\d+){3}", target):
        return "invalid"

    if is_valid_hostname(target):
        return "hostname"

    return "invalid"