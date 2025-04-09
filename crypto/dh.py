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

    def __init__(self, private_bits=None):
        # Calculate all parameters based on private key size
        params = SecurityParams.get_secure_params(private_bits)
        self.private_bits = params["private_bits"]
        prime_bits = params["prime_bits"]
        self.public_bits = params["public_bits"]
        param_bits = params["param_bits"]

        # Generate prime modulus
        self.mod = sympy.randprime(2 ** (prime_bits - 1), 2 ** prime_bits)

        # Create Chebyshev polynomial calculator
        self.cheby = ChebyshevPoly(self.mod)

        # Generate public parameter exactly one bit less than prime
        self.param = random.randint(2 ** (param_bits - 1), 2 ** param_bits - 1)

    def generate_keypair(self, entropy=None):
        """Generate a private and public key pair."""
        # Sanitize entropy input
        if entropy is not None:
            if not isinstance(entropy, (str, bytes)):
                raise TypeError("Entropy must be a string or bytes")
            # Limit entropy length to prevent DoS
            entropy = str(entropy)[:1024]
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
        # Validate inputs
        if not isinstance(private, int) or private <= 0 or private >= self.mod:
            raise ValueError(f"Private key must be an integer between 1 and {self.mod-1}")

        if not isinstance(other_public, int) or other_public <= 0 or other_public >= self.mod:
            raise ValueError(f"Public key must be an integer between 1 and {self.mod-1}")

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
