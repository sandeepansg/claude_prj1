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
        self.sbox_mask = self.sbox_size - 1  # Fast modulo for powers of 2
        
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
        for i in range(self.rounds):
            h = hashlib.sha256()
            h.update(key + str(i).encode())
            
            # For large block sizes, we need to generate enough key material
            # by repeating the hash output as needed
            if self.half_block_size <= 32:  # SHA-256 produces 32 bytes
                subkeys.append(h.digest()[:self.half_block_size])
            else:
                # Generate multiple hash outputs and concatenate
                key_material = b''
                bytes_needed = self.half_block_size
                round_key = bytearray(bytes_needed)
                
                for j in range((bytes_needed + 31) // 32):  # Ceiling division by 32
                    h_j = hashlib.sha256()
                    h_j.update(key + str(i).encode() + str(j).encode())
                    key_material = h_j.digest()
                    
                    # Copy bytes to round key
                    start_pos = j * 32
                    for k in range(32):
                        if start_pos + k < bytes_needed:
                            round_key[start_pos + k] = key_material[k]
                            
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
            # Ensure we don't index out of bounds for the S-box
            index = result[i] % self.sbox_size
            result[i] = self.sbox[index] % 256  # Ensure output is a valid byte
            
        # Simple diffusion function (shift bits for better mixing)
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
        """
        # Split the block into left and right halves
        half_size = len(block) // 2
        L = bytearray(block[:half_size])
        R = bytearray(block[half_size:])
        
        # Apply Feistel rounds
        round_keys = subkeys if encrypt else reversed(subkeys)
        for subkey in round_keys:
            # Apply the round function to the right half
            F_output = self._round_function(bytes(R), subkey)
            
            # XOR the left half with the round function output
            L_new = bytearray(half_size)
            for i in range(half_size):
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
