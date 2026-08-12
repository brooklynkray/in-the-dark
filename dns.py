import socket


def resolve_hostname(hostname):
    """
    Resolve a hostname into IPv4 and IPv6 addresses.
    Returns a dictionary containing the results.
    """

    ipv4 = []
    ipv6 = []

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        for result in results:
            address_family = result[0]
            address = result[4][0]

            if address_family == socket.AF_INET:
                if address not in ipv4:
                    ipv4.append(address)

            elif address_family == socket.AF_INET6:
                if address not in ipv6:
                    ipv6.append(address)

    except socket.gaierror:
        pass

    return {
        "ipv4": ipv4,
        "ipv6": ipv6
    }


def reverse_lookup(ip_address):
    """
    Perform a reverse DNS lookup on an IP address.
    Returns a list of hostnames.
    """

    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip_address)

        results = [hostname]
        results.extend(aliases)

        return list(dict.fromkeys(results))

    except (socket.herror, socket.gaierror):
        return []