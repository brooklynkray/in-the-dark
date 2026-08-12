#!/usr/bin/env python3

import target


def display_target_info(target_info):
    """
    Display the information discovered about the target.
    """

    print()
    print("Target information")
    print("------------------")
    print(f"Target:       {target_info.value}")

    # Make the target type clearer for the user.
    if target_info.type == "IPv4":
        print("Type:         IPv4 address")
    elif target_info.type == "IPv6":
        print("Type:         IPv6 address")
    else:
        print(f"Type:         {target_info.type}")

    print()
    print("DNS information")
    print("---------------")

    # Hostnames are resolved into IP addresses.
    if target_info.type == "hostname":
        if target_info.resolved_addresses:
            print("Resolved addresses:")

            for address in target_info.resolved_addresses:
                print(f"  {address}")
        else:
            # DNS failure does not make the target invalid.
            print("No DNS addresses found.")

    # IP addresses can be checked using reverse DNS.
    else:
        if target_info.reverse_dns:
            print("Reverse DNS:")

            for hostname in target_info.reverse_dns:
                print(f"  {hostname}")
        else:
            print("No reverse DNS records found.")


def get_target_from_user():
    """
    Ask the user for a target and return a confirmed TargetInfo object.
    """

    while True:
        print()
        print("=" * 50)
        print("TARGET")
        print("=" * 50)

        # Get the target entered by the user.
        target_input = input(
            "Enter the target IP address or hostname: "
        ).strip()

        # Let target.py validate and classify the input.
        target_info = target.create_target(target_input)

        if target_info is None:
            print()
            print("✗ Invalid target.")
            print(
                "Please enter a valid IPv4 address, IPv6 address, "
                "or hostname."
            )
            continue

        # Enrich the target with available DNS information.
        target_info = target.enrich_target(target_info)

        # Display everything we discovered so far.
        display_target_info(target_info)

        print()
        print("Is this target correct?")
        print("[1] Yes, continue")
        print("[2] Enter different target")
        print("[3] Exit")

        choice = input("> ").strip().lower()

        # Accept both numbers and natural yes/no responses.
        if choice in ("1", "y", "yes"):
            return target_info

        if choice in ("2", "n", "no"):
            continue

        if choice in ("3", "q", "quit", "exit"):
            print("Exiting In the Dark.")
            return None

        print("Invalid choice. Please enter yes, no, or exit.")


def main():
    """
    Main application entry point.
    """

    print("In the Dark")
    print("Guided security reconnaissance and enumeration")

    # Get a validated and confirmed target from the user.
    target_info = get_target_from_user()

    # None means the user chose to exit.
    if target_info is None:
        return

    print()
    print(f"Target confirmed: {target_info.value}")


# Handle Ctrl+C gracefully instead of displaying a Python traceback.
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting In the Dark.")