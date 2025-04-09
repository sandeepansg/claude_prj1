"""
Security parameter management for Chebyshev-based cryptosystems.
"""


class SecurityParams:
    """Centralizes security parameters and their relationships."""

    # Base security constants
    MIN_PRIVATE_BITS = 16
    DEFAULT_PRIVATE_BITS = 32
    MIN_PRIME_BITS = 256
    DEFAULT_PRIME_BITS = 512

    # Security scaling factors
    PRIME_TO_PRIVATE_RATIO = 4
    PUBLIC_TO_PRIVATE_RATIO = 2
    
    # Feistel cipher security constants
    MIN_FEISTEL_ROUNDS = 8
    DEFAULT_FEISTEL_ROUNDS = 16
    MIN_BLOCK_SIZE = 8
    DEFAULT_BLOCK_SIZE = 8
    MAX_BLOCK_SIZE = 1024  # Add maximum block size to prevent performance issues
    
    # S-box security constants
    MIN_SBOX_SIZE = 16
    DEFAULT_SBOX_SIZE = 256
    MAX_SBOX_SIZE = 65536  # Add maximum size to prevent performance issues

    # Add maximum private key size
    MAX_PRIVATE_BITS = 4096  # Add reasonable maximum to prevent performance issues
    
    @classmethod
    def get_secure_params(cls, private_bits=None):
        """Calculate appropriate parameter sizes based on private key length."""
        # Use default if not provided or invalid
        if private_bits is None:
            private_bits = cls.DEFAULT_PRIVATE_BITS
        
        # Type check
        if not isinstance(private_bits, int):
            raise TypeError("private_bits must be an integer")
            
        # Enforce minimum and maximum private key size
        if private_bits < cls.MIN_PRIVATE_BITS:
            print(f"Warning: Private key size {private_bits} is below minimum. Using {cls.MIN_PRIVATE_BITS} bits.")
            private_bits = cls.MIN_PRIVATE_BITS
        elif private_bits > cls.MAX_PRIVATE_BITS:
            print(f"Warning: Private key size {private_bits} exceeds maximum. Using {cls.MAX_PRIVATE_BITS} bits.")
            private_bits = cls.MAX_PRIVATE_BITS
        
        # Use default if not provided
        private_bits = private_bits or cls.DEFAULT_PRIVATE_BITS
        
        # Enforce minimum private key size
        private_bits = max(private_bits, cls.MIN_PRIVATE_BITS)

        # Calculate recommended prime size based on private key length
        prime_bits = max(cls.MIN_PRIME_BITS, int(cls.PRIME_TO_PRIVATE_RATIO * private_bits))

        # Calculate recommended public key size
        public_bits = min(int(cls.PUBLIC_TO_PRIVATE_RATIO * private_bits), prime_bits - 1)

        # Parameter size is exactly one bit less than prime size
        param_bits = prime_bits - 1

        return {
            "private_bits": private_bits,
            "prime_bits": prime_bits,
            "public_bits": public_bits,
            "param_bits": param_bits
        }
        
    @classmethod
    def validate_feistel_params(cls, rounds=None, block_size=None):
        """Validate and adjust Feistel cipher parameters to ensure security."""
        # Use defaults if not provided
        rounds = rounds if rounds is not None else cls.DEFAULT_FEISTEL_ROUNDS
        block_size = block_size if block_size is not None else cls.DEFAULT_BLOCK_SIZE
        
        # Enforce minimum and maximum values
        rounds = max(rounds, cls.MIN_FEISTEL_ROUNDS)
        block_size = max(block_size, cls.MIN_BLOCK_SIZE)
        block_size = min(block_size, cls.MAX_BLOCK_SIZE)
        
        # Ensure block_size is even for Feistel structure
        if block_size % 2 != 0:
            block_size += 1
            
        return {
            "rounds": rounds,
            "block_size": block_size
        }
        
    @classmethod
    def validate_sbox_params(cls, box_size=None):
        """Validate and adjust S-box parameters to ensure security."""
        # Use default if not provided
        box_size = box_size if box_size is not None else cls.DEFAULT_SBOX_SIZE
        
        # Enforce minimum and maximum values
        box_size = max(box_size, cls.MIN_SBOX_SIZE)
        box_size = min(box_size, cls.MAX_SBOX_SIZE)
        
        # Find the nearest power of 2 that's >= box_size
        power = 1
        while power < box_size:
            power *= 2
            
        return {
            "box_size": power
        }
        
    @classmethod
    def is_power_of_two(cls, n):
        """Check if a number is a power of 2."""
        if n <= 0:
            return False
        return (n & (n - 1)) == 0
