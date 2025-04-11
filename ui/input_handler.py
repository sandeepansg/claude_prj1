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
    def get_manual_private_key(party_name, bit_length):
        """
        Get a manually entered private key that meets the bit length requirements.
        
        Args:
            party_name: Name of the party (e.g., "Alice" or "Bob")
            bit_length: Required bit length for the private key
            
        Returns:
            Manually entered private key as int, or None if user skips
        """
        print(f"\nEnter a {bit_length}-bit private key for {party_name} [press enter to generate randomly]")
        print(f"The key must be between {2**(bit_length-1)} and {2**bit_length - 1}")
        
        attempts = 0
        max_attempts = 3
        
        while attempts < max_attempts:
            key_input = input(f"{party_name}'s private key (decimal): ")
            if not key_input.strip():
                return None  # Skip manual entry
                
            try:
                private_key = int(key_input)
                
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
            except ValueError:
                print("Please enter a valid integer")
                
            attempts += 1
            
        print(f"Skipping manual key entry after {max_attempts} invalid attempts")
        return None

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
                    print(f"Error: S-box size must be at least {SecurityParams.MIN_SBOX_SIZE} for
