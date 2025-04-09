"""
Feistel cipher implementation using dynamically generated S-boxes.
"""
import os
import struct
import hashlib
from typing import List, Dict, Tuple, Optional, Union, ByteString
from chebyshev.security import SecurityParams


class FeistelCipher:
    """
    Implementation of a Feistel cipher with dynamically generated S-boxes.
    
    This cipher uses a balanced Feistel network structure with configurable rounds
    and block sizes. It supports CBC mode encryption with PKCS#7 padding and
    uses dynamically generated S-boxes for substitution operations.
    """

    def __init__(self, sbox: List[int], rounds: Optional[int] = None, block_size: Optional[int] = None):
        """
        Initialize the Feistel cipher.

        Args:
            sbox: The S-box for substitution operations
            rounds: Number of rounds (default is determined by SecurityParams)
            block_size: Size of each block in bytes (default is determined by SecurityParams)
                        Must be an even number to allow proper splitting of blocks
        
        Raises:
            ValueError: If provided parameters don't meet security requirements
        """
        # Validate and adjust parameters to ensure security
        validated_params = SecurityParams.validate_feistel_params(rounds, block_size)
        self.rounds = validated_params["rounds"]
        self.block_size = validated_params["block_size"]
        
        # Ensure block size is even for proper splitting
        if self.block_size % 2 != 0:
            self.block_size += 1
            
        self.half_block_size = self.block_size // 2
        
        self.sbox = sbox
        self.sbox_size = len(sbox)
        
        # Determine if sbox_size is a power of 2 for fast modulo
        self.is_power_of_two = (self.sbox_size & (self.sbox_size - 1)) == 0
        self.sbox_mask = self.sbox_size - 1 if self.is_power_of_two else None
        
        # Create inverse S-box for decryption
        self.inverse_sbox = [0] * self.sbox_size
        for i, v in enumerate(sbox):
            self.inverse_sbox[v % self.sbox_size] = i
            
    def _pad_data(self, data: bytes) -> bytes:
        """
        Pad data to be a multiple of block_size using PKCS#7 padding.
        
        Args:
            data: The data to pad
            
        Returns:
            Padded data as bytes
        """
        padding_len = self.block_size - (len(data) % self.block_size)
        if padding_len == 0:
            padding_len = self.block_size  # Full padding block if already aligned
            
        # For large block sizes, we need to handle padding differently
        # PKCS#7 only works for block sizes up to 255 bytes
        if self.block_size > 255:
            # Use a modified padding scheme for large blocks
            # First byte is 1, remaining bytes are 0
            padding = b'\x01' + b'\x00' * (padding_len - 1)
        else:
            padding = bytes([padding_len] * padding_len)
            
        return data + padding
        
    def _unpad_data(self, data: bytes) -> bytes:
        """
        Remove PKCS#7 padding from data.
        
        Args:
            data: The padded data
            
        Returns:
            Unpadded data as bytes
            
        Raises:
            ValueError: If padding is invalid
        """
        if not data:
            return b''
            
        # For large block sizes, we use a modified padding scheme
        if self.block_size > 255:
            # Check for our modified padding (first byte 1, rest 0)
            # Count trailing zeros and check for pattern
            zero_count = 0
            for i in range(len(data) - 1, 0, -1):  # Start from end, avoid underflow
                if data[i] != 0:
                    break
                zero_count += 1
                
            # Check if the byte before zeros is 1
            if zero_count > 0 and len(data) > zero_count and data[len(data) - zero_count - 1] == 1:
                # Valid padding
                return data[:len(data) - zero_count - 1]
            else:
                raise ValueError("Invalid padding for large block")
        else:
            # Standard PKCS#7 padding
            padding_len = data[-1]
            if padding_len > self.block_size or padding_len == 0:
                raise ValueError("Invalid padding length")
                
            # Check that all padding bytes have the correct value
            for i in range(1, padding_len + 1):
                if i <= len(data) and data[-i] != padding_len:
                    raise ValueError("Invalid padding values")
                    
            return data[:-padding_len]
    
    def _generate_subkeys(self, key: bytes) -> List[bytes]:
        """
        Generate round subkeys from the main key.
        
        Args:
            key: The key bytes
            
        Returns:
            List of round subkeys, each of half_block_size length
        """
        subkeys = []
        hash_size = 32  # SHA-256 outputs 32 bytes
        
        # For very large block sizes, we may need to generate multiple hash outputs
        # for each round key to ensure sufficient key material
        for i in range(self.rounds):
            # Initialize round key buffer
            round_key = bytearray(self.half_block_size)
            
            # Calculate how many hash outputs we need
            hash_outputs_needed = (self.half_block_size + hash_size - 1) // hash_size
            
            # Generate and combine hash outputs
            for j in range(hash_outputs_needed):
                h = hashlib.sha256()
                h.update(key + str(i).encode() + str(j).encode())
                digest = h.digest()
                
                # Copy bytes to round key
                start_idx = j * hash_size
                for k in range(hash_size):
                    pos = start_idx + k
                    if pos < self.half_block_size:
                        round_key[pos] = digest[k]
                        
            subkeys.append(bytes(round_key))
                
        return subkeys
    
    def _round_function(self, half_block: bytes, subkey: bytes) -> bytes:
        """
        Feistel round function F that provides confusion and diffusion.
        
        Args:
            half_block: Half of the data block
            subkey: The round subkey
            
        Returns:
            Result of the round function as bytes
        """
        # Create a mutable copy of the half block
        result = bytearray(len(half_block))
        
        # XOR with subkey (handling case when subkey is shorter than half block)
        for i in range(len(half_block)):
            result[i] = half_block[i] ^ subkey[i % len(subkey)]
            
        # Apply S-box substitution with proper modulo operations
        for i in range(len(result)):
            # Use different approaches based on whether sbox_size is a power of 2
            if self.is_power_of_two:
                # Fast modulo for power of 2
                index = result[i] & self.sbox_mask
            else:
                # Standard modulo for non-power of 2
                index = result[i] % self.sbox_size
                
            result[i] = self.sbox[index] & 0xFF  # Ensure output is a valid byte
            
        # Efficient diffusion function for large blocks
        # We'll use a different strategy for blocks over 64 bytes
        if len(result) > 64:
            # For large blocks, use a byte-swapping strategy to provide diffusion
            mixed = bytearray(len(result))
            half_len = len(result) // 2
            
            # Interleave bytes from first and second half
            for i in range(half_len):
                mixed[i*2] = result[i]
                mixed[i*2+1] = result[i + half_len]
                
            # Handle odd length if necessary
            if len(result) % 2 != 0:
                mixed[-1] = result[-1]
                
            return bytes(mixed)
        else:
            # For smaller blocks, use the original bit rotation strategy
            mixed = bytearray(len(result))
            for i in range(len(result)):
                # Rotate bits left by 1
                mixed[i] = ((result[i] << 1) | (result[i] >> 7)) & 0xFF
                
            return bytes(mixed)
        
    def _process_block(self, block: bytes, subkeys: List[bytes], encrypt: bool = True) -> bytes:
        """
        Process a single block through the Feistel network.
        
        Args:
            block: The block to process, must be of length block_size
            subkeys: List of round subkeys
            encrypt: True for encryption, False for decryption
            
        Returns:
            Processed block of the same length
            
        Raises:
            ValueError: If block size doesn't match expected size
        """
        # Verify block size
        if len(block) != self.block_size:
            raise ValueError(f"Block size must be {self.block_size} bytes, got {len(block)}")
            
        # Split the block into left and right halves
        half_size = len(block) // 2
        L = bytearray(block[:half_size])
        R = bytearray(block[half_size:])
        
        # Apply Feistel rounds
        round_keys = subkeys if encrypt else reversed(subkeys)
        for subkey in round_keys:
            # Apply the round function to the right half
            F_output = self._round_function(bytes(R), subkey)
            
            # Calculate length to use for XOR operation
            # This handles cases where F_output might be shorter than L
            xor_length = min(len(L), len(F_output))
            
            # XOR the left half with the round function output
            L_new = bytearray(len(L))
            for i in range(len(L)):
                L_new[i] = L[i] ^ F_output[i % len(F_output)]
                
            # Swap L and R for next round (except for the last round in decryption)
            L, R = R, L_new
            
        # Final swap (undo the last swap that occurred in the loop)
        return bytes(R) + bytes(L)
    
    def encrypt(self, plaintext: bytes, key: Optional[bytes] = None) -> bytes:
        """
        Encrypt plaintext using the Feistel cipher in CBC mode with IV.
        
        Args:
            plaintext: The plaintext to encrypt
            key: The encryption key (uses S-box as key if None)
            
        Returns:
            Ciphertext with IV prepended
        """
        # Generate a random IV
        iv = os.urandom(self.block_size)
        
        # Use S-box as key if none provided - handle various S-box sizes
        if key is None:
            # Use first 32 bytes of S-box as key, handling case when S-box is smaller
            key_size = min(32, self.sbox_size)
            key_bytes = bytearray(32)  # Initialize with zeros
            for i in range(key_size):
                key_bytes[i % 32] = self.sbox[i] % 256
            key = bytes(key_bytes)
            
        # Generate round subkeys
        subkeys = self._generate_subkeys(key)
        
        # Pad the plaintext
        padded_plaintext = self._pad_data(plaintext)
        
        # Process each block in CBC mode
        blocks = [padded_plaintext[i:i+self.block_size] 
                 for i in range(0, len(padded_plaintext), self.block_size)]
        
        # First block XORed with IV
        prev_block = iv
        ciphertext_blocks = []
        
        for block in blocks:
            # XOR with previous ciphertext block (or IV for first block)
            xored_block = bytearray(self.block_size)
            for i in range(self.block_size):
                xored_block[i] = block[i] ^ prev_block[i]
                
            # Process through Feistel network
            encrypted_block = self._process_block(bytes(xored_block), subkeys, encrypt=True)
            ciphertext_blocks.append(encrypted_block)
            prev_block = encrypted_block
            
        # Prepend the IV to the ciphertext
        return iv + b''.join(ciphertext_blocks)
    
    def decrypt(self, ciphertext: bytes, key: Optional[bytes] = None) -> bytes:
        """
        Decrypt ciphertext using the Feistel cipher in CBC mode.
        
        Args:
            ciphertext: The ciphertext to decrypt, with IV prepended
            key: The decryption key (uses S-box as key if None)
            
        Returns:
            Decrypted plaintext with padding removed
            
        Raises:
            ValueError: If ciphertext is too short to contain an IV
        """
        # Check if ciphertext is long enough to contain IV
        if len(ciphertext) < self.block_size:
            raise ValueError(f"Ciphertext too short, must be at least {self.block_size} bytes to contain IV")
            
        # Extract IV
        iv = ciphertext[:self.block_size]
        ciphertext = ciphertext[self.block_size:]
        
        # Handle empty ciphertext after IV
        if not ciphertext:
            return b''
            
        # Use S-box as key if none provided - handle various S-box sizes
        if key is None:
            # Use first 32 bytes of S-box as key, handling case when S-box is smaller
            key_size = min(32, self.sbox_size)
            key_bytes = bytearray(32)  # Initialize with zeros
            for i in range(key_size):
                key_bytes[i % 32] = self.sbox[i] % 256
            key = bytes(key_bytes)
            
        # Generate round subkeys
        subkeys = self._generate_subkeys(key)
        
        # Process each block in CBC mode
        blocks = [ciphertext[i:i+self.block_size] 
                 for i in range(0, len(ciphertext), self.block_size)]
        
        plaintext_blocks = []
        prev_block = iv
        
        for block in blocks:
            # Process through Feistel network (reverse order for decryption)
            decrypted_block = self._process_block(block, subkeys, encrypt=False)
            
            # XOR with previous ciphertext block (or IV for first block)
            plaintext_block = bytearray(len(decrypted_block))
            for i in range(len(decrypted_block)):
                plaintext_block[i] = decrypted_block[i] ^ prev_block[i % len(prev_block)]
                
            plaintext_blocks.append(bytes(plaintext_block))
            prev_block = block
            
        # Combine blocks and remove padding
        try:
            return self._unpad_data(b''.join(plaintext_blocks))
        except ValueError as e:
            # Handle padding errors gracefully
            print(f"Warning: Padding error during decryption: {e}")
            return b''.join(plaintext_blocks)
            
    def get_cipher_info(self) -> Dict[str, int]:
        """
        Get information about the cipher configuration.
        
        Returns:
            Dictionary with configuration information including rounds, block_size, and sbox_size
        """
        return {
            "rounds": self.rounds,
            "block_size": self.block_size,
            "sbox_size": self.sbox_size
        }
