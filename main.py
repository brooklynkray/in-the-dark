#!/usr/bin/env python3

import cli
import environment
import executor
import ports
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


def ask_custom_ports(default):
    """
    Ask for a custom port specification and return the validated,
    normalized string. Only called when the user has chosen
    scan.PortScope.CUSTOM - this function has no idea what port scope
    means, it only asks for and validates one string via
    ports.parse_custom_ports().

    `default` is the previous custom_ports value, if any (from an
    earlier pass through this same CUSTOM choice, on reconfigure).
    When present, blank input re-accepts it; when absent (the first
    time CUSTOM is chosen), there is no sensible default to fall back
    to, so a non-blank, valid answer is required.
    """

    cli.subsection("Custom ports")

    cli.info(
        "Enter the ports to scan: single ports, comma-separated "
        "lists, or hyphenated ranges (e.g. 80,443 or 1-1024)."
    )

    while True:
        if default is not None:
            raw = input(f"Ports [{default}]: ").strip()
            if not raw:
                return default
        else:
            raw = input("Ports: ").strip()

        parsed = ports.parse_custom_ports(raw)

        if parsed is not None:
            return parsed

        cli.error("Invalid port specification.")
        cli.info(
            "Use single ports, comma-separated lists, or hyphenated "
            "ranges within 1-65535, e.g. 80,443 or 1-1024,3389."
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


def ask_os_detection(default):
    """
    Ask whether to enable OS detection (-O) and return a bool.
    `default` is shown explicitly rather than assumed, for the same
    reason as ask_service_detection(). This function has no idea
    whether the current session can actually run OS detection -
    that's shown separately, in the preview.
    """

    cli.subsection("OS detection")

    info = scan.OS_DETECTION_INFO
    cli.info(f"{info.what} {info.why}")
    cli.info(f"Cost: {info.cost}")

    default_label = "Y" if default else "N"

    while True:
        choice = input(
            f"Enable OS detection? [{default_label}] "
        ).strip().lower()

        if not choice:
            return default

        if choice in ("y", "yes"):
            return True

        if choice in ("n", "no"):
            return False

        cli.warning("Invalid choice. Please enter y or n.")


def ask_timing(default):
    """
    Ask which Nmap timing template to use and return the chosen
    scan.Timing. `default` is shown explicitly, for the same reason
    as ask_port_scope().
    """

    cli.subsection("Timing")

    options = list(scan.Timing)
    default_index = options.index(default) + 1

    for index, timing in enumerate(options, start=1):
        info = scan.TIMING_INFO[timing]
        marker = " (default)" if timing == default else ""
        cli.menu([(str(index), f"{info.name}{marker}")])
        cli.info(f"{info.what} {info.why}")
        cli.info(f"Cost: {info.cost}")

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


def ask_technique(default):
    """
    Ask which TCP scan technique to use and return the chosen
    scan.Technique. `default` is shown explicitly, for the same
    reason as ask_port_scope(). This function has no idea whether the
    current session can actually run either technique - that's shown
    separately, in the preview.
    """

    cli.subsection("Scan technique")

    options = list(scan.Technique)
    default_index = options.index(default) + 1

    for index, technique in enumerate(options, start=1):
        info = scan.TECHNIQUE_INFO[technique]
        marker = " (default)" if technique == default else ""
        cli.menu([(str(index), f"{info.name}{marker}")])
        cli.info(f"{info.what} {info.why}")
        cli.info(f"Cost: {info.cost}")

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


def get_scan_config_from_user(current=None):
    """
    Ask the guided questions and return a scan.ScanConfig. This is a
    thin layer over ask_technique() / ask_port_scope() /
    ask_custom_ports() / ask_service_detection() / ask_os_detection()
    / ask_timing() - it holds no command-building logic of its own.
    Questions are asked in the same order build_argv() emits their
    flags, so the guided flow reads in the same order as the command
    it produces.

    ask_custom_ports() is only called when the chosen port scope is
    CUSTOM - it's the one conditionally-asked question in this flow,
    since custom_ports must stay None for every other port scope
    (see ScanConfig's docstring for that invariant).

    `current` is the previous ScanConfig, if any (passed in when the
    user declined a preview and chose to reconfigure). Its values are
    used as the pre-selected default for each question, so declining
    preserves the earlier answers instead of resetting them. Moving
    away from CUSTOM on reconfigure means custom_ports reverts to
    None - choosing CUSTOM again afterwards starts fresh.
    """

    cli.section("Scan")

    defaults = current if current is not None else scan.ScanConfig()

    technique = ask_technique(defaults.technique)
    port_scope = ask_port_scope(defaults.port_scope)

    custom_ports = None
    if port_scope == scan.PortScope.CUSTOM:
        custom_ports = ask_custom_ports(defaults.custom_ports)

    return scan.ScanConfig(
        technique=technique,
        port_scope=port_scope,
        custom_ports=custom_ports,
        service_detection=ask_service_detection(defaults.service_detection),
        os_detection=ask_os_detection(defaults.os_detection),
        timing=ask_timing(defaults.timing),
    )


def _privilege_requiring_capabilities(scan_config):
    """
    Return the plain-English names of currently-selected capabilities
    that need elevated privileges to actually run, as parallel noun
    phrases (so they read naturally whether one or several are
    joined together in a sentence). Used only to build a single,
    consolidated preview warning - this is a small, explicit check of
    the two known privileged capabilities, not a generic
    "requires_privilege" metadata mechanism scanning over ScanConfig.
    """

    needed = []

    if scan_config.technique == scan.Technique.SYN:
        needed.append("SYN scanning")

    if scan_config.os_detection:
        needed.append("OS detection")

    return needed


def display_scan_preview(target_info, scan_config, elevated):
    """
    Show the chosen scan configuration, its purpose, and the exact
    command that would run. The command is derived from
    scan.build_argv() - there is no separate, hand-written preview
    string to drift out of sync with it.

    `elevated` is the current session's privilege state, from
    environment.py. It is used only to show an informational warning
    when a privileged capability (SYN, OS detection) is selected
    without privilege - it never blocks a choice, never changes
    scan_config, and never changes the argv that gets built or
    executed.
    """

    cli.subsection("Scan configuration")

    technique_info = scan.TECHNIQUE_INFO[scan_config.technique]
    cli.list_items("Technique", [technique_info.name])

    port_info = scan.PORT_SCOPE_INFO[scan_config.port_scope]
    if scan_config.port_scope == scan.PortScope.CUSTOM:
        port_scope_label = f"{port_info.name} ({scan_config.custom_ports})"
    else:
        port_scope_label = port_info.name
    cli.list_items("Port scope", [port_scope_label])

    detection_label = "Enabled" if scan_config.service_detection else "Disabled"
    cli.list_items("Service/version detection", [detection_label])

    os_detection_label = "Enabled" if scan_config.os_detection else "Disabled"
    cli.list_items("OS detection", [os_detection_label])

    timing_info = scan.TIMING_INFO[scan_config.timing]
    cli.list_items("Timing", [timing_info.name])

    purpose = technique_info.why
    purpose = f"{purpose} {port_info.why}"
    if scan_config.service_detection:
        purpose = f"{purpose} {scan.SERVICE_DETECTION_INFO.why}"
    if scan_config.os_detection:
        purpose = f"{purpose} {scan.OS_DETECTION_INFO.why}"
    purpose = f"{purpose} {timing_info.why}"

    print()
    print("Purpose:")
    print(f"  {purpose}")

    if not elevated:
        needed = _privilege_requiring_capabilities(scan_config)
        if needed:
            print()
            cli.warning(
                "This session does not appear to have elevated "
                f"privileges. This scan requires elevated privileges for "
                f"{' and '.join(needed)}, so Nmap will likely refuse to run "
                "it and exit with a privilege error rather than "
                "completing it."
            )

    argv = scan.build_argv(target_info, scan_config)

    print()
    print("Command:")
    print()
    print(f"  {' '.join(argv)}")


def get_confirmed_scan_config(target_info, elevated):
    """
    Run the guided question flow, show the preview, and ask for
    explicit consent. Declining returns to the questions so the user
    can reconfigure, preserving the previous answers as the new
    defaults rather than resetting them. Exiting cancels the scan
    configuration entirely. Nothing is ever executed from here either
    way - this only ever returns a ScanConfig or None.

    `elevated` is passed straight through to display_scan_preview()
    for its privileged-capability warning - see that function's
    docstring for what it does and doesn't affect.
    """

    scan_config = None

    while True:
        scan_config = get_scan_config_from_user(scan_config)

        display_scan_preview(target_info, scan_config, elevated)

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


def display_execution_result(result):
    """
    Show what happened when the approved command was run: whether it
    started, how it finished, and any captured output.
    """

    cli.subsection("Execution result")

    if result.executable_not_found:
        cli.error("Nmap could not be started - the executable was not found.")
        return

    if result.timed_out:
        cli.error("Nmap did not finish within the timeout and was stopped.")
    elif result.return_code == 0:
        cli.success(f"Nmap finished successfully (exit code {result.return_code}).")
    else:
        cli.warning(f"Nmap exited with a non-zero code ({result.return_code}).")

    if result.stdout:
        cli.list_items("stdout", result.stdout.splitlines())

    if result.stderr:
        cli.list_items("stderr", result.stderr.splitlines())


def show_startup_sequence():
    """
    Print the banner and report on the checks in environment.py.

    Only real, already-available information is shown here. Network
    and VPN awareness are future work and deliberately have no status
    line yet - adding one now would mean faking a result, which this
    CLI is explicitly not meant to do.

    Returns whether the current session appears to have elevated
    privileges, so main() can pass it on to the scan-preview step's
    privileged-capability warning. If detection failed outright, this
    conservatively reports False rather than claiming a privilege
    level that was never actually confirmed.
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

    return env.elevated if env is not None else False


def main():
    """
    Main application entry point.
    """

    elevated = show_startup_sequence()

    # Get a validated and confirmed target from the user.
    target_info = get_target_from_user()

    # None means the user chose to exit.
    if target_info is None:
        return

    print()
    cli.success(f"Target confirmed: {target_info.value}")

    # Guided questions -> ScanConfig -> preview -> explicit consent.
    scan_config = get_confirmed_scan_config(target_info, elevated)

    # None means the user chose to exit instead of confirming a scan.
    if scan_config is None:
        return

    print()
    cli.success("Scan configuration approved.")

    # The exact argv scan.build_argv() produced for the approved
    # configuration - built once, here, and handed to the executor
    # unchanged. It is never rebuilt from the preview string, and the
    # executor never sees anything but this list.
    argv = scan.build_argv(target_info, scan_config)

    cli.info("Running Nmap. This may take a while...")
    result = executor.run(argv)

    display_execution_result(result)


# Handle Ctrl+C gracefully instead of displaying a Python traceback.
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        cli.info("Exiting In the Dark.")
