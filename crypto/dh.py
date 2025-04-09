"""
Diffie-Hellman key exchange using Chebyshev polynomials.
"""
import random
import sympy
import time
from chebyshev.poly import ChebyshevPoly
from chebyshev.security import SecurityParams


class ChebyshevDH:
    """Diffie-Hellman key exchange using Chebyshev polynomials."""

    def __init__(self, sbox: List[int], rounds: Optional[int] = None, block_size: Optional[int] = None):
    """Initialize the Feistel cipher."""
    # Validate sbox type and contents
    if not isinstance(sbox, list):
        raise TypeError("S-box must be a list")
    
    if not sbox or not all(isinstance(x, int) for x in sbox):
        raise ValueError("S-box must be a non-empty list of integers")
    
    # Check sbox size is a power of 2 for efficient modulo operations
    sbox_size = len(sbox)
    if not SecurityParams.is_power_of_two(sbox_size):
        raise ValueError("S-box size must be a power of 2 for security and performance")
        
    # Validate values in the S-box (should be in range)
    if max(sbox) >= sbox_size or min(sbox) < 0:
        raise ValueError(f"S-box entries must be between 0 and {sbox_size-1}")

    def generate_keypair(self, entropy=None):
        """Generate a private and public key pair."""
        # Add entropy to randomness if provided
        if entropy:
            random.seed(hash(f"{entropy}{time.time()}"))

        # Generate private key of appropriate length
        private_min = 2 ** (self.private_bits - 1)
        private_max = 2 ** self.private_bits - 1
        private = random.randint(private_min, private_max)

        # Calculate raw public key
        raw_public = self.cheby.eval(private, self.param)

        # Format public key to specified bit length
        mask = (1 << self.public_bits) - 1
        public = (raw_public & mask) | (1 << (self.public_bits - 1))
        public %= self.mod

        return private, public, raw_public

    def compute_shared(self, private, other_public):
        """Compute shared secret using DH principle."""
        return self.cheby.eval(private, other_public)

    def simulate_exchange(self, alice_entropy=None, bob_entropy=None):
        """Simulate complete key exchange between two parties."""
        alice_priv, alice_pub, alice_raw = self.generate_keypair(alice_entropy)
        bob_priv, bob_pub, bob_raw = self.generate_keypair(bob_entropy)

        alice_shared = self.compute_shared(alice_priv, bob_raw)
        bob_shared = self.compute_shared(bob_priv, alice_raw)

        return {
            "alice_private": alice_priv,
            "alice_public": alice_pub,
            "alice_raw_public": alice_raw,
            "bob_private": bob_priv,
            "bob_public": bob_pub,
            "bob_raw_public": bob_raw,
            "alice_shared": alice_shared,
            "bob_shared": bob_shared,
            "match": alice_shared == bob_shared
        }

    def get_system_info(self):
        """Get system parameters for display purposes."""
        return {
            "mod": self.mod,
            "mod_bits": self.mod.bit_length(),
            "param": self.param,
            "param_bits": self.param.bit_length(),
            "private_bits": self.private_bits,
            "public_bits": self.public_bits
        }
