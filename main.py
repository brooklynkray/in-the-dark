#!/usr/bin/env python3

import cli
import environment
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
            print("Resolved addresses:")

            for address in target_info.resolved_addresses:
                print(f"  {address}")
        else:
            # DNS failure does not make the target invalid.
            cli.info("No DNS addresses found.")

    # IP addresses can be checked using reverse DNS.
    else:
        if target_info.reverse_dns:
            print("Reverse DNS:")

            for hostname in target_info.reverse_dns:
                print(f"  {hostname}")
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


# Handle Ctrl+C gracefully instead of displaying a Python traceback.
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        cli.info("Exiting In the Dark.")
