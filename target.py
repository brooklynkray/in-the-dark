import dns
import ipaddress
import re
from dataclasses import dataclass, field


@dataclass
class TargetInfo:
    value: str
    type: str
    reverse_dns: list[str] = field(default_factory=list)
    resolved_addresses: list[str] = field(default_factory=list)


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

def create_target(target):
    target = target.strip()
    target_type = identify_target(target)

    if target_type == "invalid":
        return None

    return TargetInfo(
        value=target,
        type=target_type
    )

def enrich_target(target_info):
    if target_info.type == "hostname":
        results = dns.resolve_hostname(target_info.value)

        target_info.resolved_addresses = (
            results["ipv4"] + results["ipv6"]
        )

    elif target_info.type in ("IPv4", "IPv6"):
        target_info.reverse_dns = dns.reverse_lookup(
            target_info.value
        )

    return target_info