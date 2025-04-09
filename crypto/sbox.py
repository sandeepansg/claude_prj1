"""
S-box generation from shared secrets for the Feistel cipher.
"""
import hashlib
import struct
from chebyshev.security import SecurityParams


class SBoxGenerator:
    """Generates secure S-boxes from shared secrets."""

    def __init__(self, shared_secret, box_size=None):
        """
        Initialize with a shared secret to generate S-boxes.

        Args:
            shared_secret (int): The shared secret from DH exchange
            box_size (int, optional): Size of the S-box, defaults to 256 for byte operations
        """
        validated_params = SecurityParams.validate_sbox_params(box_size)
        self.box_size = validated_params["box_size"]
        self.shared_secret = shared_secret
        
    def generate(self):
        """
        Generate an S-box using the shared secret as seed.
        
        Returns:
            list: An S-box mapping values 0 to (box_size-1)
        """
        # Convert shared secret to bytes
        secret_bytes = self.shared_secret.to_bytes(
            (self.shared_secret.bit_length() + 7) // 8, 
            byteorder='big'
        )
        
        # Initialize S-box with identity mapping
        sbox = list(range(self.box_size))
        
        # Use SHA-256 to derive key material
        key_material = b''
        for i in range((self.box_size * 4 + 31) // 32):  # Need enough bytes
            h = hashlib.sha256()
            h.update(secret_bytes + str(i).encode())
            key_material += h.digest()
        
        # Fisher-Yates shuffle using the key material as randomness
        for i in range(self.box_size - 1, 0, -1):
            # Extract 4 bytes to get a 32-bit integer for randomness
            j_bytes = key_material[4*(self.box_size-1-i):4*(self.box_size-i)]
            j = struct.unpack('>I', j_bytes)[0] % (i + 1)
            sbox[i], sbox[j] = sbox[j], sbox[i]
            
        return sbox
        
    def generate_inverse(self, sbox):
        """
        Generate the inverse of an S-box.
        
        Args:
            sbox (list): The S-box to invert
            
        Returns:
            list: The inverse S-box
        """
        inverse = [0] * self.box_size
        for i, value in enumerate(sbox):
            inverse[value] = i
        return inverse
    
    def test_properties(self, sbox):
        """
        Test cryptographic properties of the S-box.
        
        Args:
            sbox (list): The S-box to test
            
        Returns:
            dict: Results of various cryptographic tests
        """
        # Check for bijection (one-to-one mapping)
        is_bijective = len(set(sbox)) == self.box_size
        
        # Check for fixed points
        fixed_points = sum(1 for i in range(self.box_size) if sbox[i] == i)
        
        # Calculate nonlinearity metrics (simplified approach)
        # For a full cryptanalysis, more sophisticated tests would be needed
        differences = []
        for i in range(1, self.box_size):
            xor_differences = []
            for x in range(self.box_size):
                input_diff = x ^ i  # XOR difference in input
                output_diff = sbox[x] ^ sbox[input_diff % self.box_size]  # XOR difference in output
                xor_differences.append(output_diff)
            # Count most common output difference
            max_count = max(xor_differences.count(d) for d in set(xor_differences))
            differences.append(max_count)
        
        avalanche_score = max(differences) / self.box_size
        
        return {
            "bijective": is_bijective,
            "fixed_points": fixed_points,
            "box_size": self.box_size,
            "avalanche_score": avalanche_score,
            "ideal_avalanche": 1/self.box_size,
            "security_score": 1 - (avalanche_score - 1/self.box_size)
        }
