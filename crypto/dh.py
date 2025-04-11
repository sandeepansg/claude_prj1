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

    def generate_keypair(self, entropy=None, private_key=None):
        """
        Generate a private and public key pair.
        
        Args:
            entropy: Optional entropy for key generation
            private_key: Optional manually provided private key
            
        Returns:
            Tuple of (private_key, public_key, raw_public_key)
            
        Raises:
            ValueError: If the provided private key doesn't match required bit length
        """
        # Sanitize entropy input
        if entropy is not None:
            if not isinstance(entropy, (str, bytes)):
                raise TypeError("Entropy must be a string or bytes")
            # Limit entropy length to prevent DoS
            entropy = str(entropy)[:1024]
            random.seed(hash(f"{entropy}{time.time()}"))

        # Generate or validate private key
        if private_key is not None:
            # Validate that private key is correct size
            if not isinstance(private_key, int) or private_key <= 0:
                raise ValueError("Private key must be a positive integer")
                
            # Check if the key matches the required bit length
            key_bits = private_key.bit_length()
            min_bits = self.private_bits - 1  # Allow keys that are one bit smaller (leading zeros)
            max_bits = self.private_bits
            
            if key_bits < min_bits or key_bits > max_bits:
                raise ValueError(f"Private key must be {self.private_bits} bits (got {key_bits} bits)")
                
            private = private_key
        else:
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
        """
        Compute shared secret using DH principle.
        
        Args:
            private: Private key
            other_public: Other party's public key
            
        Returns:
            Computed shared secret
            
        Raises:
            ValueError: If inputs are invalid
        """
        # Validate inputs
        if not isinstance(private, int) or private <= 0 or private >= self.mod:
            raise ValueError(f"Private key must be an integer between 1 and {self.mod-1}")

        if not isinstance(other_public, int) or other_public <= 0 or other_public >= self.mod:
            raise ValueError(f"Public key must be an integer between 1 and {self.mod-1}")

        return self.cheby.eval(private, other_public)

    def simulate_exchange(self, alice_entropy=None, bob_entropy=None, alice_private=None, bob_private=None):
        """
        Simulate complete key exchange between two parties.
        
        Args:
            alice_entropy: Optional entropy for Alice's key
            bob_entropy: Optional entropy for Bob's key
            alice_private: Optional manually provided private key for Alice
            bob_private: Optional manually provided private key for Bob
            
        Returns:
            Dictionary with key exchange details
        """
        alice_priv, alice_pub, alice_raw = self.generate_keypair(alice_entropy, alice_private)
        bob_priv, bob_pub, bob_raw = self.generate_keypair(bob_entropy, bob_private)

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
        
    def verify_key_match(self, private_key, public_key, role="user"):
        """
        Verify if a private key matches a public key.
        
        Args:
            private_key: The private key to verify
            public_key: The public key to check against
            role: Description of the key's owner (e.g., "Alice", "Bob")
            
        Returns:
            Tuple of (is_match, computed_public, raw_public)
        """
        try:
            # Calculate raw public key from private key
            raw_public = self.cheby.eval(private_key, self.param)
            
            # Format public key to specified bit length (same as in generate_keypair)
            mask = (1 << self.public_bits) - 1
            computed_public = (raw_public & mask) | (1 << (self.public_bits - 1))
            computed_public %= self.mod
            
            # Check if computed public matches expected public
            return (computed_public == public_key, computed_public, raw_public)
        except Exception as e:
            print(f"Error verifying {role}'s key: {e}")
            return (False, None, None)
