#!/usr/bin/env python3

import target


def display_target_info(target_info):
    print()
    print("Target information")
    print("------------------")
    print(f"Target:       {target_info.value}")
    print(f"Type:         {target_info.type}")

    print()
    print("DNS information")
    print("---------------")

    if target_info.type == "hostname":
        if target_info.resolved_addresses:
            print("Resolved addresses:")

            for address in target_info.resolved_addresses:
                print(f"  {address}")
        else:
            print("No DNS addresses found.")

    else:
        if target_info.reverse_dns:
            print("Reverse DNS:")

            for hostname in target_info.reverse_dns:
                print(f"  {hostname}")
        else:
            print("No reverse DNS records found.")


def get_target_from_user():
    while True:
        print()
        print("=" * 50)
        print("TARGET")
        print("=" * 50)

        target_input = input(
            "Enter the target IP address or hostname: "
        ).strip()

        target_info = target.create_target(target_input)

        if target_info is None:
            print()
            print("✗ Invalid target.")
            print(
                "Please enter a valid IPv4 address, IPv6 address, "
                "or hostname."
            )
            continue

        target_info = target.enrich_target(target_info)

        display_target_info(target_info)

        print()
        print("Is this target correct?")
        print("[1] Yes, continue")
        print("[2] Enter different target")
        print("[3] Exit")

        choice = input("> ").strip().lower()

        if choice in ("1", "y", "yes"):
            return target_info

        if choice in ("2", "n", "no"):
            continue

        if choice in ("3", "q", "quit", "exit"):
            print("Exiting In the Dark.")
            return None

        print("Invalid choice. Please enter yes, no, or exit.")


def main():
    print("In the Dark")
    print("Guided security reconnaissance and enumeration")

    target_info = get_target_from_user()

    if target_info is None:
        return

    print()
    print(f"Target confirmed: {target_info.value}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting In the Dark.")