#!/usr/bin/env python3

import target


def get_target_from_user():
    while True:
        print()
        print("=" * 50)
        print("TARGET")
        print("=" * 50)

        target_input = input("Enter the target IP address or hostname: ").strip()

        target_info = target.create_target(target_input)

        if target_info is None:
            print()
            print("✗ Invalid target.")
            print("Please enter a valid IPv4 address, IPv6 address, or hostname.")
            continue

        print()
        print("Target information")
        print("------------------")
        print(f"Target:       {target_info.value}")
        print(f"Type:         {target_info.type}")
        print(f"Reverse DNS:  Not checked")
        print()

        print("Is this target correct?")
        print("[1] Yes, continue")
        print("[2] Enter different target")
        print("[3] Exit")

        choice = input("> ").strip()

        if choice == "1":
            return target_info

        if choice == "2":
            continue

        if choice == "3":
            print("Exiting In the Dark.")
            return None

        print("Invalid choice. Please select 1, 2, or 3.")


def main():
    print("In the Dark")
    print("Guided security reconnaissance and enumeration")

    target_info = get_target_from_user()

    if target_info is None:
        return

    print()
    print(f"Target confirmed: {target_info.value}")


if __name__ == "__main__":
    main()