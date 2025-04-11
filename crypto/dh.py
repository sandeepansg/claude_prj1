"""
Diffie-Hellman key exchange using Chebyshev polynomials.
"""
import random
import sympy
import time
import base64
import struct
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

    def simulate_exchange(self, alice_entropy=None, bob_entropy=None, alice_private=None, bob_private=None):
        """Simulate complete key exchange between two parties."""
        # Generate or use provided private keys
        if alice_private is None:
            alice_priv, alice_pub, alice_raw = self.generate_keypair(alice_entropy)
        else:
            alice_priv = alice_private
            alice_raw = self.cheby.eval(alice_priv, self.param)
            mask = (1 << self.public_bits) - 1
            alice_pub = (alice_raw & mask) | (1 << (self.public_bits - 1))
            alice_pub %= self.mod

        if bob_private is None:
            bob_priv, bob_pub, bob_raw = self.generate_keypair(bob_entropy)
        else:
            bob_priv = bob_private
            bob_raw = self.cheby.eval(bob_priv, self.param)
            mask = (1 << self.public_bits) - 1
            bob_pub = (bob_raw & mask) | (1 << (self.public_bits - 1))
            bob_pub %= self.mod

        # Compute shared secrets
        try:
            alice_shared = self.compute_shared(alice_priv, bob_raw)
            bob_shared = self.compute_shared(bob_priv, alice_raw)
            match = alice_shared == bob_shared
        except ValueError as e:
            # Handle incompatible keys
            return {
                "alice_private": alice_priv,
                "alice_public": alice_pub,
                "alice_raw_public": alice_raw,
                "bob_private": bob_priv,
                "bob_public": bob_pub,
                "bob_raw_public": bob_raw,
                "error": str(e),
                "match": False
            }

        return {
            "alice_private": alice_priv,
            "alice_public": alice_pub,
            "alice_raw_public": alice_raw,
            "bob_private": bob_priv,
            "bob_public": bob_pub,
            "bob_raw_public": bob_raw,
            "alice_shared": alice_shared,
            "bob_shared": bob_shared,
            "match": match
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

    def encode_private_key(self, private_key):
        """Encode a private key as a base64 string."""
        if not isinstance(private_key, int) or private_key <= 0:
            raise ValueError("Private key must be a positive integer")

        # Get the byte length needed to represent this number
        byte_length = (private_key.bit_length() + 7) // 8

        # Pack as a big-endian integer with appropriate byte length
        try:
            if byte_length <= 4:
                fmt = ">I"  # 4 bytes
            elif byte_length <= 8:
                fmt = ">Q"  # 8 bytes
            else:
                # For larger numbers, serialize as bytes with length prefix
                key_bytes = private_key.to_bytes(byte_length, byteorder='big')
                # Pack with a 2-byte length prefix
                fmt = ">H"
                return base64.b64encode(struct.pack(fmt, byte_length) + key_bytes).decode('ascii')

            return base64.b64encode(struct.pack(fmt, private_key)).decode('ascii')
        except struct.error:
            # Fallback for very large numbers
            key_bytes = private_key.to_bytes((private_key.bit_length() + 7) // 8, byteorder='big')
            return base64.b64encode(key_bytes).decode('ascii')

    def decode_private_key(self, encoded_key):
        """Decode a base64 string back to a private key."""
        try:
            key_bytes = base64.b64decode(encoded_key)

            # Check if the key has a length prefix (larger keys)
            if len(key_bytes) > 8:
                length = struct.unpack(">H", key_bytes[:2])[0]
                if length + 2 == len(key_bytes):
                    return int.from_bytes(key_bytes[2:], byteorder='big')

            # Handle standard-sized keys
            if len(key_bytes) == 4:
                return struct.unpack(">I", key_bytes)[0]
            elif len(key_bytes) == 8:
                return struct.unpack(">Q", key_bytes)[0]
            else:
                # Fallback: interpret bytes as a big-endian integer
                return int.from_bytes(key_bytes, byteorder='big')

        except (ValueError, struct.error, base64.binascii.Error) as e:
            raise ValueError(f"Invalid encoded private key: {str(e)}")