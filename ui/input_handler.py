"""
Input handler for the Chebyshev cryptosystem.
Handles all user input operations.
"""
from chebyshev.security import SecurityParams
from crypto.key_store import KeyStore
import os


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
    def get_key_input_method():
        """
        Ask user how they want to input their private key.
        
        Returns:
            str: 'generate' or 'file'
        """
        print("\nKey Input Method")
        print("-" * 30)
        print("1. Generate new keys")
        print("2. Load keys from file")
        
        while True:
            choice = input("Enter your choice [1/2, default=1]: ").strip()
            if not choice or choice == '1':
                return 'generate'
            elif choice == '2':
                return 'file'
            else:
                print("Invalid choice. Please enter 1 or 2.")

    @staticmethod
    def get_key_file_path(participant="user"):
        """
        Get key file path from user.
        
        Args:
            participant (str): Name of participant (for display purposes)
            
        Returns:
            str: Path to key file, or None if user cancels
        """
        # First list available keys
        available_keys = KeyStore.list_available_keys()
        
        if available_keys:
            print(f"\nAvailable key files for {participant}:")
            for i, key_info in enumerate(available_keys, 1):
                print(f"{i}. {key_info['filename']} (Owner: {key_info['owner']}, Created: {key_info['created']})")
            print(f"{len(available_keys) + 1}. Enter a custom file path")
            print(f"{len(available_keys) + 2}. Cancel and generate a new key")
            
            while True:
                choice = input(f"Enter your choice [1-{len(available_keys) + 2}]: ").strip()
                try:
                    choice_num = int(choice)
                    if 1 <= choice_num <= len(available_keys):
                        return os.path.join(KeyStore.DEFAULT_KEYS_DIR, available_keys[choice_num - 1]['filename'])
                    elif choice_num == len(available_keys) + 1:
                        # Custom file path
                        break
                    elif choice_num == len(available_keys) + 2:
                        # Cancel
                        return None
                    else:
                        print(f"Please enter a number between 1 and {len(available_keys) + 2}")
                except ValueError:
                    print("Please enter a valid number")
        
        # Custom file path input
        while True:
            file_path = input(f"Enter the path to {participant}'s key file (or 'cancel'): ").strip()
            if file_path.lower() == 'cancel':
                return None
            
            if os.path.exists(file_path):
                return file_path
            else:
                print(f"File not found: {file_path}")
                retry = input("Try again? [y/n, default=y]: ").strip().lower()
                if retry == 'n':
                    return None

    @staticmethod
    def get_key_save_preference():
        """
        Ask if user wants to save generated keys.
        
        Returns:
            bool: True if user wants to save keys, False otherwise
        """
        while True:
            save = input("Do you want to save the generated keys to files? [y/n, default=y]: ").strip().lower()
            if not save or save == 'y':
                return True
            elif save == 'n':
                return False
            else:
                print("Please enter 'y' or 'n'")

    @staticmethod
    def get_key_owner_names():
        """
        Get owner names for key files.
        
        Returns:
            tuple: (alice_name, bob_name)
        """
        alice_name = input("Enter a name for Alice's key [default=alice]: ").strip()
        if not alice_name:
            alice_name = "alice"
            
        bob_name = input("Enter a name for Bob's key [default=bob]: ").strip()
        if not bob_name:
            bob_name = "bob"
            
        return alice_name, bob_name

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
