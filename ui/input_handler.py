"""
Input handler for the Chebyshev cryptosystem.
Handles all user input operations.
"""
from chebyshev.security import SecurityParams


class InputHandler:
    """Handles user inputs and validation."""

    # Default test count for consistency
    DEFAULT_TEST_COUNT = 5
    MIN_TEST_COUNT = 3
    MAX_TEST_COUNT = 50

    @staticmethod
    def get_private_key_length():
        """Get private key length from user input."""
        attempts = 0
        max_attempts = 3

        while attempts < max_attempts:
            private_input = input(f"Enter private key length in bits [default={SecurityParams.DEFAULT_PRIVATE_BITS}]: ")
            if not private_input.strip():
                return SecurityParams.DEFAULT_PRIVATE_BITS  # Return the default value

            try:
                private_bits = int(private_input)
                if private_bits < SecurityParams.MIN_PRIVATE_BITS:
                    print(f"Error: Private key must be at least {SecurityParams.MIN_PRIVATE_BITS} bits for security")
                elif private_bits > SecurityParams.MAX_PRIVATE_BITS:
                    print(f"Error: Private key cannot exceed {SecurityParams.MAX_PRIVATE_BITS} bits for performance")
                else:
                    return private_bits
            except ValueError:
                print("Please enter a valid number")

            attempts += 1

        print(f"Using default value of {SecurityParams.DEFAULT_PRIVATE_BITS} after {max_attempts} invalid attempts")
        return SecurityParams.DEFAULT_PRIVATE_BITS

    @staticmethod
    def get_test_count():
        """Get consistent test count for all security property tests."""
        print("\nTest Configuration")
        print("-" * 30)

        test_count = InputHandler.DEFAULT_TEST_COUNT  # Set default first
        while True:
            count_input = input(f"Enter number of tests to run [default={InputHandler.DEFAULT_TEST_COUNT}, min={InputHandler.MIN_TEST_COUNT}, max={InputHandler.MAX_TEST_COUNT}]: ")
            if not count_input.strip():
                break  # Use default already set

            try:
                test_count = int(count_input)
                if test_count < InputHandler.MIN_TEST_COUNT:
                    print(f"Error: Number of tests must be at least {InputHandler.MIN_TEST_COUNT}")
                    continue
                elif test_count > InputHandler.MAX_TEST_COUNT:
                    print(f"Error: Number of tests must be at most {InputHandler.MAX_TEST_COUNT} for performance")
                    continue
                break
            except ValueError:
                print("Please enter a valid number")

        return test_count

    @staticmethod
    def get_feistel_params():
        """Get Feistel cipher parameters from user input."""
        print("\nFeistel Cipher Configuration")
        print("-" * 30)

        # Get rounds
        rounds = SecurityParams.DEFAULT_FEISTEL_ROUNDS  # Set default first
        while True:
            rounds_input = input(f"Enter number of Feistel rounds [default={SecurityParams.DEFAULT_FEISTEL_ROUNDS}]: ")
            if not rounds_input.strip():
                break  # Use default already set

            try:
                rounds = int(rounds_input)
                if rounds >= SecurityParams.MIN_FEISTEL_ROUNDS:
                    break
                print(f"Error: Number of rounds must be at least {SecurityParams.MIN_FEISTEL_ROUNDS} for security")
            except ValueError:
                print("Please enter a valid number")

        # Get block size
        block_size = SecurityParams.DEFAULT_BLOCK_SIZE  # Set default first
        while True:
            block_input = input(f"Enter block size in bytes [default={SecurityParams.DEFAULT_BLOCK_SIZE}, max={SecurityParams.MAX_BLOCK_SIZE}]: ")
            if not block_input.strip():
                break  # Use default already set

            try:
                block_size = int(block_input)
                if block_size < SecurityParams.MIN_BLOCK_SIZE:
                    print(f"Error: Block size must be at least {SecurityParams.MIN_BLOCK_SIZE} bytes for security")
                    continue
                elif block_size > SecurityParams.MAX_BLOCK_SIZE:
                    print(f"Error: Block size must be at most {SecurityParams.MAX_BLOCK_SIZE} bytes for performance")
                    continue
                break
            except ValueError:
                print("Please enter a valid number")

        return rounds, block_size

    @staticmethod
    def get_sbox_params():
        """Get S-box parameters from user input."""
        print("\nS-Box Configuration")
        print("-" * 30)

        box_size = SecurityParams.DEFAULT_SBOX_SIZE  # Set default first
        while True:
            size_input = input(f"Enter S-box size [default={SecurityParams.DEFAULT_SBOX_SIZE}, max={SecurityParams.MAX_SBOX_SIZE}]: ")
            if not size_input.strip():
                return box_size  # Return default already set

            try:
                box_size = int(size_input)
                if box_size < SecurityParams.MIN_SBOX_SIZE:
                    print(f"Error: S-box size must be at least {SecurityParams.MIN_SBOX_SIZE} for security")
                    continue
                elif box_size > SecurityParams.MAX_SBOX_SIZE:
                    print(f"Error: S-box size must be at most {SecurityParams.MAX_SBOX_SIZE} for performance")
                    continue
                return box_size
            except ValueError:
                print("Please enter a valid number")

    @staticmethod
    def get_entropy():
        """Get optional entropy for key generation."""
        return input("Enter text for additional entropy (optional): ")

    @staticmethod
    def get_sample_message():
        """Get a sample message to encrypt."""
        default_message = "This is a secure message exchanged using Chebyshev polynomials!"
        message = input(f"Enter a message to encrypt [default: '{default_message}']: ")
        return message.strip() if message.strip() else default_message

    @staticmethod
    def get_manual_key_choice():
        """Get user choice for manual key entry."""
        print("\nKey Exchange Options")
        print("-" * 30)
        print("1. Use automatically generated keys")
        print("2. Manually enter Alice's private key")
        print("3. Manually enter Bob's private key")
        print("4. Manually enter both private keys")

        while True:
            choice = input("Select an option [default=1]: ")
            if not choice.strip():
                return 1  # Default to automatic keys

            try:
                choice_num = int(choice)
                if 1 <= choice_num <= 4:
                    return choice_num
                print("Please enter a number between 1 and 4")
            except ValueError:
                print("Please enter a valid number")

    @staticmethod
    def get_manual_private_key(party_name, default_key, encoded_default):
        """Get manually entered private key."""
        print(f"\nManual {party_name} Key Entry")
        print("-" * 30)
        print(f"Default {party_name} private key (Base64): {encoded_default}")
        print(f"Default {party_name} private key (hex): 0x{default_key:X}")
        print(f"Default {party_name} private key bit length: {default_key.bit_length()} bits")

        # First ask if user wants to use encoded key or enter a new integer
        print("\nKey Input Options:")
        print("1. Enter a Base64-encoded key")
        print("2. Enter a decimal integer key")
        print("3. Enter a hexadecimal key (with 0x prefix)")

        entry_mode = 1  # Default to Base64
        while True:
            mode_input = input("Select entry mode [default=1]: ")
            if not mode_input.strip():
                break

            try:
                entry_mode = int(mode_input)
                if 1 <= entry_mode <= 3:
                    break
                print("Please select 1, 2, or 3")
            except ValueError:
                print("Please enter a valid number")

        # Now get the key based on the selected mode
        while True:
            if entry_mode == 1:
                key_input = input(f"Enter {party_name}'s Base64-encoded private key [or leave empty for default]: ")
                if not key_input.strip():
                    return default_key

                try:
                    # Will be decoded in the DH class
                    return key_input.strip()
                except ValueError as e:
                    print(f"Invalid Base64 private key: {str(e)}")

            elif entry_mode == 2:
                key_input = input(f"Enter {party_name}'s private key as decimal integer [or leave empty for default]: ")
                if not key_input.strip():
                    return default_key

                try:
                    return int(key_input.strip())
                except ValueError:
                    print("Please enter a valid integer")

            elif entry_mode == 3:
                key_input = input(f"Enter {party_name}'s private key as hex (with 0x prefix) [or leave empty for default]: ")
                if not key_input.strip():
                    return default_key

                try:
                    if not key_input.lower().startswith("0x"):
                        print("Hexadecimal keys must start with 0x")
                        continue
                    return int(key_input, 16)
                except ValueError:
                    print("Please enter a valid hexadecimal number")

    @staticmethod
    def get_encryption_key_choice(shared_key=None):
        """Choose whether to use generated shared key or enter a custom key for encryption."""
        print("\nEncryption Key Options")
        print("-" * 30)
        print("1. Use the computed shared secret from key exchange")
        print("2. Manually enter a different key")

        while True:
            choice = input("Select an option [default=1]: ")
            if not choice.strip():
                return shared_key, 1  # Default to using the generated shared key

            try:
                choice_num = int(choice)
                if choice_num == 1:
                    return shared_key, 1
                elif choice_num == 2:
                    # Get a custom key
                    print("\nManual Encryption Key Entry")
                    print("-" * 30)
                    if shared_key is not None:
                        print(f"Current shared key (hex): 0x{shared_key:X}")
                        print(f"Current shared key bit length: {shared_key.bit_length()} bits")

                    # Let user choose input format
                    print("\nKey Input Options:")
                    print("1. Enter a decimal integer key")
                    print("2. Enter a hexadecimal key (with 0x prefix)")

                    format_choice = 1
                    format_input = input("Select input format [default=1]: ")
                    if format_input.strip():
                        try:
                            format_choice = int(format_input)
                            if format_choice not in (1, 2):
                                print("Invalid choice, using decimal format")
                                format_choice = 1
                        except ValueError:
                            print("Invalid choice, using decimal format")

                    while True:
                        if format_choice == 1:
                            key_input = input("Enter encryption key as decimal integer: ")
                            if not key_input.strip():
                                print("Key input cannot be empty when using custom keys")
                                continue

                            try:
                                custom_key = int(key_input.strip())
                                if custom_key <= 0:
                                    print("Key must be a positive integer")
                                    continue
                                return custom_key, 2
                            except ValueError:
                                print("Please enter a valid integer")

                        elif format_choice == 2:
                            key_input = input("Enter encryption key as hex (with 0x prefix): ")
                            if not key_input.strip():
                                print("Key input cannot be empty when using custom keys")
                                continue

                            try:
                                if not key_input.lower().startswith("0x"):
                                    print("Hexadecimal keys must start with 0x")
                                    continue
                                custom_key = int(key_input, 16)
                                if custom_key <= 0:
                                    print("Key must be a positive integer")
                                    continue
                                return custom_key, 2
                            except ValueError:
                                print("Please enter a valid hexadecimal number")
                else:
                    print("Please enter 1 or 2")
            except ValueError:
                print("Please enter a valid number")