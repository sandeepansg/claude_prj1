"""
Chebyshev polynomial based Diffie-Hellman key exchange implementation.
"""
import hashlib
import os
import random
import time
from chebyshev.poly import ChebyshevPoly
from chebyshev.security import SecurityParams


class ChebyshevDH:
    """Implements Chebyshev polynomial Diffie-Hellman key exchange."""
    
    def __init__(self, private_bits=None, preset_private_key=None):
        """
        Initialize the Diffie-Hellman key exchange system.
        
        Args:
            private_bits (int, optional): Bit length for private keys
            preset_private_key (int, optional): Use a preset private key
        """
        # Use default bits if not specified
        if private_bits is None and preset_private_key is None:
            private_bits = SecurityParams.DEFAULT_PRIVATE_BITS
        elif preset_private_key is not None:
            # If preset key is provided, derive bit length from it
            private_bits = preset_private_key.bit_length()
        
        # Generate or set security parameters
        params = SecurityParams.get_secure_params(private_bits)
        self.prime_bits = params['prime_bits']
        self.prime_modulus = params['prime_modulus']
        self.private_bits = params['private_bits']
        
        # Set public parameter (one bit less than prime for security)
        self.public_param = params['public_param']
        
        # Store the polynomial evaluator
        self.poly = ChebyshevPoly(self.prime_modulus)
        
        # Store preset private key if provided
        self.preset_private_key = preset_private_key
    
    def get_system_info(self):
        """
        Get information about the current system parameters.
        
        Returns:
            dict: System parameters and sizes
        """
        return {
            'mod': self.prime_modulus,
            'mod_bits': self.prime_modulus.bit_length(),
            'param': self.public_param,
            'param_bits': self.public_param.bit_length(),
            'private_bits': self.private_bits,
            'public_bits': self.poly.eval(2, self.public_param).bit_length()
        }
    
    def _generate_private_key(self, entropy=None):
        """
        Generate a secure private key.
        
        Args:
            entropy (str, optional): Additional entropy for key generation
            
        Returns:
            int: Generated private key
        """
        # If a preset key is provided, use it instead of generating one
        if self.preset_private_key is not None:
            return self.preset_private_key
            
        # Use system time and OS-provided randomness as seed
        seed = str(time.time()) + str(os.urandom(32))
        
        # Add user-provided entropy if available
        if entropy:
            seed += entropy
        
        # Create a hash of the seed
        hash_obj = hashlib.sha512(seed.encode())
        hash_hex = hash_obj.hexdigest()
        
        # Convert hash to integer and ensure it's the right size
        key_int = int(hash_hex, 16)
        mask = (1 << self.private_bits) - 1
        private_key = key_int & mask
        
        # Ensure private key is not too small
        min_value = 1 << (self.private_bits - 1)
        if private_key < min_value:
            private_key |= min_value
        
        return private_key
    
    def generate_key_pair(self, entropy=None):
        """
        Generate a private-public key pair.
        
        Args:
            entropy (str, optional): Additional entropy for key generation
            
        Returns:
            tuple: (private_key, raw_public_key, formatted_public_key)
        """
        # Generate private key
        private_key = self._generate_private_key(entropy)
        
        # Generate raw public key: T_a(x) mod p
        raw_public_key = self.poly.eval(private_key, self.public_param)
        
        # Format public key to ensure it's in the correct range
        formatted_public_key = raw_public_key
        
        return private_key, raw_public_key, formatted_public_key
    
    def compute_shared_secret(self, private_key, other_public_key):
        """
        Compute shared secret using own private key and other's public key.
        
        Args:
            private_key (int): Own private key
            other_public_key (int): Other party's public key
            
        Returns:
            int: Computed shared secret
        """
        # Compute T_a(T_b(x)) = T_b(T_a(x)) = T_ab(x) mod p
        shared_secret = self.poly.eval(private_key, other_public_key)
        return shared_secret
    
    def simulate_exchange(self, alice_entropy=None, bob_entropy=None, 
                          preset_alice_key=None, preset_bob_key=None):
        """
        Simulate a complete key exchange between Alice and Bob.
        
        Args:
            alice_entropy (str, optional): Entropy for Alice's key generation
            bob_entropy (str, optional): Entropy for Bob's key generation
            preset_alice_key (int, optional): Preset private key for Alice
            preset_bob_key (int, optional): Preset private key for Bob
            
        Returns:
            dict: Complete exchange results
        """
        # Override preset key for this exchange if specified
        temp_preset = self.preset_private_key
        
        # Generate or use Alice's keys
        self.preset_private_key = preset_alice_key
        alice_private, alice_raw_public, alice_public = self.generate_key_pair(alice_entropy)
        
        # Generate or use Bob's keys
        self.preset_private_key = preset_bob_key
        bob_private, bob_raw_public, bob_public = self.generate_key_pair(bob_entropy)
        
        # Restore the original preset key
        self.preset_private_key = temp_preset
        
        # Compute shared secrets
        alice_shared = self.compute_shared_secret(alice_private, bob_public)
        bob_shared = self.compute_shared_secret(bob_private, alice_public)
        
        # Check if shared secrets match (they should)
        match = alice_shared == bob_shared
        
        return {
            'alice_private': alice_private,
            'alice_raw_public': alice_raw_public,
            'alice_public': alice_public,
            'bob_private': bob_private,
            'bob_raw_public': bob_raw_public,
            'bob_public': bob_public,
            'alice_shared': alice_shared,
            'bob_shared': bob_shared,
            'match': match
        }
