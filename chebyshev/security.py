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

    @classmethod
    def get_secure_params(cls, private_bits=None):
        """Calculate appropriate parameter sizes based on private key length."""
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
