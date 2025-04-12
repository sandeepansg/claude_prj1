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
    def get_manual_private_key(party_name, default_key, encoded_key):
        """
        Get a manually entered private key that meets the bit length requirements.
        
        Args:
            party_name: Name of the party (e.g., "Alice" or "Bob")
            default_key: A default key value to show as example
            encoded_key: Base64 encoded version of the default key
            
        Returns:
            Manually entered private key as int or encoded string, or None if user skips
        """
        bit_length = default_key.bit_length()
        print(f"\nEnter a {bit_length}-bit private key for {party_name} [press enter to generate randomly]")
        print(f"The key must be between {2**(bit_length-1)} and {2**bit_length - 1}")
        print(f"Default key (hex): 0x{default_key:X}")
        print(f"Default key (base64): {encoded_key}")
        
        print("\nEntry options:")
        print("1. Enter decimal integer")
        print("2. Enter hexadecimal (with 0x prefix)")
        print("3. Enter base64 encoded key")
        print("4. Skip (use random key)")
        
        entry_choice = "1"  # Default to decimal
        while True:
            choice = input("Select entry format [default=1]: ")
            if not choice.strip() or choice in ["1", "2", "3", "4"]:
                entry_choice = choice if choice.strip() else "1"
                break
            print("Invalid choice. Please select 1-4.")
                
        if entry_choice == "4":
            return None  # Skip manual entry
        
        attempts = 0
        max_attempts = 3
        
        while attempts < max_attempts:
            if entry_choice == "1":
                key_input = input(f"{party_name}'s private key (decimal): ")
                if not key_input.strip():
                    return None  # Skip manual entry
                try:
                    private_key = int(key_input)
                except ValueError:
                    print("Please enter a valid integer")
                    attempts += 1
                    continue
            elif entry_choice == "2":
                key_input = input(f"{party_name}'s private key (hex with 0x prefix): ")
                if not key_input.strip():
                    return None  # Skip manual entry
                try:
                    private_key = int(key_input, 16)
                except ValueError:
                    print("Please enter a valid hexadecimal number with 0x prefix")
                    attempts += 1
                    continue
            elif entry_choice == "3":
                key_input = input(f"{party_name}'s private key (base64): ")
                if not key_input.strip():
                    return None  # Skip manual entry
                # Return as string to indicate it's already encoded
                return key_input
                
            # Check bit length
            key_bits = private_key.bit_length()
            min_bits = bit_length - 1  # Allow keys that are one bit smaller (leading zeros)
            max_bits = bit_length
            
            if key_bits < min_bits or key_bits > max_bits:
                print(f"Error: Private key must be {bit_length} bits (got {key_bits} bits)")
                print(f"Must be between {2**(bit_length-1)} and {2**bit_length - 1}")
            elif private_key <= 0:
                print("Error: Private key must be a positive integer")
            else:
                return private_key
                
            attempts += 1
            
        print(f"Skipping manual key entry after {max_attempts} invalid attempts")
        return None

    @staticmethod
    def get_manual_key_choice():
        """
        Ask user if they want to manually enter private keys.
        
        Returns:
            int: 1 = Auto for both, 2 = Manual Alice, 3 = Manual Bob, 4 = Manual both
        """
        print("\nKey Generation Options")
        print("-" * 30)
        print("1. Automatically generate both private keys")
        print("2. Manually enter Alice's private key only")
        print("3. Manually enter Bob's private key only")
        print("4. Manually enter both private keys")
        
        while True:
            choice = input("Select an option [default=1]: ")
            if not choice.strip():
                return 1
            try:
                choice_num = int(choice)
                if 1 <= choice_num <= 4:
                    return choice_num
                print("Invalid option. Please enter a number between 1-4.")
            except ValueError:
                print("Invalid option. Please enter a number between 1-4.")

    @staticmethod
    def get_encryption_key_choice(shared_key):
        """
        Ask user whether to use the shared key from DH exchange or enter a custom key.
        
        Args:
            shared_key: The calculated shared key from DH exchange
            
        Returns:
            tuple: (key, source) where key is the encryption key to use and source is 1 for shared or 2 for custom
        """
        print("\nEncryption Key Options")
        print("-" * 30)
        print("1. Use shared secret key from key exchange")
        print("2. Enter a custom encryption key")
        
        while True:
            choice = input("Select an option [default=1]: ")
            if not choice.strip() or choice == "1":
                return shared_key, 1
            elif choice == "2":
                custom_key = InputHandler.get_custom_encryption_key()
                return custom_key, 2
            else:
                print("Invalid option. Please enter 1 or 2.")

    @staticmethod
    def get_custom_encryption_key():
        """
        Get a custom encryption key from user.
        
        Returns:
            int: The custom encryption key
        """
        print("\nEnter a custom encryption key")
        
        attempts = 0
        max_attempts = 3
        
        while attempts < max_attempts:
            key_input = input("Custom encryption key (decimal or 0x for hex): ")
            if not key_input.strip():
                print("Error: Custom key cannot be empty")
                attempts += 1
                continue
                
            try:
                # Check if it's a hex input
                if key_input.lower().startswith("0x"):
                    custom_key = int(key_input, 16)
                else:
                    custom_key = int(key_input)
                
                if custom_key <= 0:
                    print("Error: Encryption key must be a positive integer")
                else:
                    return custom_key
            except ValueError:
                print("Please enter a valid integer (decimal or with 0x prefix for hex)")
                
            attempts += 1
            
        print(f"Failed to get valid custom key after {max_attempts} attempts")
        print("Using a default encryption key")
        return 0x12345678  # Default fallback

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
        
        return box_size  # Return default if we somehow get here

    @staticmethod
    def get_entropy():
        """
        Get optional user entropy for key generation.
        
        Returns:
            str: User-provided entropy string or empty string if skipped
        """
        print("\nEntropy Collection (Optional)")
        print("-" * 30)
        print("You can provide additional entropy for key generation.")
        print("This helps improve randomness for cryptographic operations.")
        print("Press Enter to skip or type any random characters:")
        
        entropy = input("> ")
        return entropy
    
    @staticmethod
    def get_sample_message():
        """
        Get a sample message from the user to encrypt.
        
        Returns:
            str: The message to encrypt
        """
        print("\nMessage Input")
        print("-" * 30)
        
        while True:
            message = input("Enter a message to encrypt: ")
            if message.strip():
                return message
            print("Message cannot be empty. Please enter text to encrypt.")
