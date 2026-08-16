#!/usr/bin/env python3

import cli
import environment
import scan
import target


def display_target_info(target_info):
    """
    Display the information discovered about the target.
    """

    cli.subsection("Target information")
    cli.field("Target", target_info.value)

    # Make the target type clearer for the user.
    if target_info.type == "IPv4":
        cli.field("Type", "IPv4 address")
    elif target_info.type == "IPv6":
        cli.field("Type", "IPv6 address")
    else:
        cli.field("Type", target_info.type)

    cli.subsection("DNS information")

    # Hostnames are resolved into IP addresses.
    if target_info.type == "hostname":
        if target_info.resolved_addresses:
            cli.list_items(
                "Resolved addresses",
                target_info.resolved_addresses,
            )
        else:
            # DNS failure does not make the target invalid.
            cli.info("No DNS addresses found.")

    # IP addresses can be checked using reverse DNS.
    else:
        if target_info.reverse_dns:
            cli.list_items("Reverse DNS", target_info.reverse_dns)
        else:
            cli.info("No reverse DNS records found.")


def get_target_from_user():
    """
    Ask the user for a target and return a confirmed TargetInfo object.
    """

    while True:
        cli.section("Target")

        # Get the target entered by the user.
        target_input = input(
            "Enter the target IP address or hostname: "
        ).strip()

        # Let target.py validate and classify the input.
        target_info = target.create_target(target_input)

        if target_info is None:
            print()
            cli.error("Invalid target.")
            cli.info(
                "Please enter a valid IPv4 address, IPv6 address, "
                "or hostname."
            )
            continue

        # Enrich the target with available DNS information.
        target_info = target.enrich_target(target_info)

        # Display everything we discovered so far.
        display_target_info(target_info)

        # Confirm the target. This is its own loop so that an invalid
        # answer just re-asks the question - it must not discard the
        # target and drop back to the "enter a target" prompt above.
        while True:
            print()
            cli.info("Is this target correct?")
            cli.menu([
                ("1", "Yes, continue"),
                ("2", "Enter different target"),
                ("3", "Exit"),
            ])

            choice = input("> ").strip().lower()

            # Accept both numbers and natural yes/no responses.
            if choice in ("1", "y", "yes"):
                return target_info

            if choice in ("2", "n", "no"):
                break  # back to the outer loop for a new target

            if choice in ("3", "q", "quit", "exit"):
                cli.info("Exiting In the Dark.")
                return None

            cli.warning("Invalid choice. Please enter yes, no, or exit.")


def ask_port_scope(default):
    """
    Ask which ports to scan and return the chosen scan.PortScope.

    This function only asks a question and reads input - it does not
    know what flag any option maps to, that is scan.build_argv()'s
    job. `default` is shown explicitly (marked, and pre-selected on
    blank input) rather than assumed - the caller decides what counts
    as the default, so a reconfigure pass can pre-select the previous
    answer instead of always resetting to scan.ScanConfig()'s
    built-in defaults.
    """

    cli.subsection("Port scope")

    options = list(scan.PortScope)
    default_index = options.index(default) + 1

    for index, port_scope in enumerate(options, start=1):
        info = scan.PORT_SCOPE_INFO[port_scope]
        marker = " (default)" if port_scope == default else ""
        cli.menu([(str(index), f"{info.name}{marker}")])
        cli.info(f"{info.what} {info.why}")

    print()

    while True:
        choice = input(f"> [{default_index}] ").strip()

        if not choice:
            return default

        if choice in [str(i) for i in range(1, len(options) + 1)]:
            return options[int(choice) - 1]

        cli.warning(
            f"Invalid choice. Please enter a number from 1 to {len(options)}."
        )


def ask_service_detection(default):
    """
    Ask whether to enable service/version detection (-sV) and return
    a bool. `default` is shown explicitly rather than assumed, for
    the same reason as ask_port_scope().
    """

    cli.subsection("Service/version detection")

    info = scan.SERVICE_DETECTION_INFO
    cli.info(f"{info.what} {info.why}")
    cli.info(f"Cost: {info.cost}")

    default_label = "Y" if default else "N"

    while True:
        choice = input(
            f"Enable service/version detection? [{default_label}] "
        ).strip().lower()

        if not choice:
            return default

        if choice in ("y", "yes"):
            return True

        if choice in ("n", "no"):
            return False

        cli.warning("Invalid choice. Please enter y or n.")


def get_scan_config_from_user(current=None):
    """
    Ask the guided questions and return a scan.ScanConfig. This is a
    thin layer over ask_port_scope() / ask_service_detection() - it
    holds no command-building logic of its own.

    `current` is the previous ScanConfig, if any (passed in when the
    user declined a preview and chose to reconfigure). Its values are
    used as the pre-selected default for each question, so declining
    preserves the earlier answers instead of resetting them.
    """

    cli.section("Scan")

    defaults = current if current is not None else scan.ScanConfig()

    return scan.ScanConfig(
        port_scope=ask_port_scope(defaults.port_scope),
        service_detection=ask_service_detection(defaults.service_detection),
    )


def display_scan_preview(target_info, scan_config):
    """
    Show the chosen scan configuration, its purpose, and the exact
    command that would run. The command is derived from
    scan.build_argv() - there is no separate, hand-written preview
    string to drift out of sync with it.
    """

    cli.subsection("Scan configuration")

    port_info = scan.PORT_SCOPE_INFO[scan_config.port_scope]
    cli.list_items("Port scope", [port_info.name])

    detection_label = "Enabled" if scan_config.service_detection else "Disabled"
    cli.list_items("Service/version detection", [detection_label])

    purpose = port_info.why
    if scan_config.service_detection:
        purpose = f"{purpose} {scan.SERVICE_DETECTION_INFO.why}"

    print()
    print("Purpose:")
    print(f"  {purpose}")

    argv = scan.build_argv(target_info, scan_config)

    print()
    print("Command:")
    print()
    print(f"  {' '.join(argv)}")


def get_confirmed_scan_config(target_info):
    """
    Run the guided question flow, show the preview, and ask for
    explicit consent. Declining returns to the questions so the user
    can reconfigure, preserving the previous answers as the new
    defaults rather than resetting them. Exiting cancels the scan
    configuration entirely. Nothing is ever executed from here either
    way - this only ever returns a ScanConfig or None.
    """

    scan_config = None

    while True:
        scan_config = get_scan_config_from_user(scan_config)

        display_scan_preview(target_info, scan_config)

        print()
        while True:
            cli.info("Is this scan configuration correct?")
            cli.menu([
                ("1", "Yes, continue"),
                ("2", "Reconfigure"),
                ("3", "Exit"),
            ])

            choice = input("> ").strip().lower()

            if choice in ("1", "y", "yes"):
                return scan_config

            if choice in ("2", "n", "no"):
                break  # back to the outer loop to reconfigure

            if choice in ("3", "q", "quit", "exit"):
                cli.info("Exiting In the Dark.")
                return None

            cli.warning("Invalid choice. Please enter yes, no, or exit.")

        cli.info("Let's reconfigure the scan.")


def show_startup_sequence():
    """
    Print the banner and report on the checks in environment.py.

    Only real, already-available information is shown here. Network
    and VPN awareness are future work and deliberately have no status
    line yet - adding one now would mean faking a result, which this
    CLI is explicitly not meant to do.
    """

    cli.banner()
    cli.rule()

    # get_environment() shells out to whoami / id / sudo. On a stripped
    # -down system one of those core binaries may be missing, which
    # surfaces as FileNotFoundError - recoverable, since the user can
    # still reach the target prompt without environment detail. Any
    # other exception is not something we know how to handle here, so
    # we deliberately let it propagate rather than masking a real bug.
    try:
        env = environment.get_environment()
    except FileNotFoundError:
        env = None

    if env is None:
        cli.status("Initialising environment", "FAIL", level="error")
    else:
        cli.status("Initialising environment", "OK")

        if env.elevated:
            privilege_result = f"OK ({env.user}, elevated)"
        elif env.sudo_available:
            privilege_result = f"OK ({env.user}, sudo available)"
        else:
            privilege_result = f"OK ({env.user}, unprivileged)"
        cli.status("Checking privileges", privilege_result)

        # Nmap isn't required to accept a target, so a missing
        # install is a warning rather than an error.
        if env.nmap_path:
            cli.status("Checking Nmap", f"OK ({env.nmap_path})")
        else:
            cli.status("Checking Nmap", "NOT FOUND", level="warn")

    cli.rule()
    print("\nReady.\n")


def main():
    """
    Main application entry point.
    """

    show_startup_sequence()

    # Get a validated and confirmed target from the user.
    target_info = get_target_from_user()

    # None means the user chose to exit.
    if target_info is None:
        return

    print()
    cli.success(f"Target confirmed: {target_info.value}")

    # Guided questions -> ScanConfig -> preview -> explicit consent.
    # Execution is a later increment - this deliberately stops here.
    scan_config = get_confirmed_scan_config(target_info)

    # None means the user chose to exit instead of confirming a scan.
    if scan_config is None:
        return

    print()
    cli.success("Scan configuration approved.")
    cli.info(
        "Execution is deliberately not implemented in this increment. "
        "In the Dark stops here."
    )


# Handle Ctrl+C gracefully instead of displaying a Python traceback.
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        cli.info("Exiting In the Dark.")
