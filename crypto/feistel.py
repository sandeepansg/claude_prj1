"""
Feistel cipher implementation using dynamically generated S-boxes.
"""
import os
import struct
import hashlib
from chebyshev.security import SecurityParams


class FeistelCipher:
    """
    Implementation of a Feistel cipher with dynamically generated S-boxes.
    """

    def __init__(self, sbox, rounds=None, block_size=None):
        """
        Initialize the Feistel cipher.

        Args:
            sbox (list): The S-box for substitution
            rounds (int, optional): Number of rounds (default is determined by SecurityParams)
            block_size (int, optional): Size of each block in bytes (default is determined by SecurityParams)
        """
        # Validate and adjust parameters to ensure security
        validated_params = SecurityParams.validate_feistel_params(rounds, block_size)
        self.rounds = validated_params["rounds"]
        self.block_size = validated_params["block_size"]
        self.half_block_size = self.block_size // 2
        
        self.sbox = sbox
        self.sbox_size = len(sbox)
        self.sbox_mask = self.sbox_size - 1  # Fast modulo for powers of 2
        
        # Create inverse S-box for decryption
        self.inverse_sbox = [0] * self.sbox_size
        for i, v in enumerate(sbox):
            self.inverse_sbox[v] = i
            
    def _pad_data(self, data):
        """
        Pad data to be a multiple of block_size using PKCS#7 padding.
        
        Args:
            data (bytes): The data to pad
            
        Returns:
            bytes: Padded data
        """
        padding_len = self.block_size - (len(data) % self.block_size)
        padding = bytes([padding_len] * padding_len)
        return data + padding
        
    def _unpad_data(self, data):
        """
        Remove PKCS#7 padding from data.
        
        Args:
            data (bytes): The padded data
            
        Returns:
            bytes: Unpadded data
        """
        padding_len = data[-1]
        if padding_len > self.block_size:
            raise ValueError("Invalid padding")
            
        for i in range(1, padding_len + 1):
            if data[-i] != padding_len:
                raise ValueError("Invalid padding")
                
        return data[:-padding_len]
    
    def _generate_subkeys(self, key):
        """
        Generate round subkeys from the main key.
        
        Args:
            key (bytes): The key bytes
            
        Returns:
            list: Round subkeys
        """
        subkeys = []
        for i in range(self.rounds):
            h = hashlib.sha256()
            h.update(key + str(i).encode())
            subkeys.append(h.digest()[:self.half_block_size])
        return subkeys
    
    def _round_function(self, half_block, subkey):
        """
        Feistel round function F.
        
        Args:
            half_block (bytes): Half of the data block
            subkey (bytes): The round subkey
            
        Returns:
            bytes: Result of the round function
        """
        # XOR with subkey
        result = bytearray(len(half_block))
        for i in range(len(half_block)):
            result[i] = half_block[i] ^ subkey[i % len(subkey)]
            
        # Apply S-box substitution - properly handling S-box size that's not 256
        for i in range(len(result)):
            if self.sbox_size == 256:
                # Fast path for byte-sized S-box
                result[i] = self.sbox[result[i]]
            else:
                # For non-standard S-box sizes, use modulo to ensure we don't index out of bounds
                result[i] = self.sbox[result[i] % self.sbox_size] % 256
            
        # Mix bits (equivalent to a simple P-box)
        mixed = bytearray(len(result))
        for i in range(len(result)):
            mixed[i] = (result[i] << 1 | result[i] >> 7) & 0xFF
            
        return bytes(mixed)
        
    def _process_block(self, block, subkeys, encrypt=True):
        """
        Process a single block through the Feistel network.
        
        Args:
            block (bytes): The block to process
            subkeys (list): List of round subkeys
            encrypt (bool): True for encryption, False for decryption
            
        Returns:
            bytes: Processed block
        """
        half_size = len(block) // 2
        L = bytearray(block[:half_size])
        R = bytearray(block[half_size:])
        
        # Apply Feistel rounds
        round_keys = subkeys if encrypt else reversed(subkeys)
        for subkey in round_keys:
            # Standard Feistel transformation
            F_output = self._round_function(bytes(R), subkey)
            L_new = bytearray(half_size)
            for i in range(half_size):
                L_new[i] = L[i] ^ F_output[i]
                
            # Swap L and R for next round
            L, R = R, L_new
            
        # Final swap (undo the last swap)
        return bytes(R) + bytes(L)
    
    def encrypt(self, plaintext, key=None):
        """
        Encrypt plaintext using the Feistel cipher.
        
        Args:
            plaintext (bytes): The plaintext to encrypt
            key (bytes, optional): The encryption key (uses sbox if None)
            
        Returns:
            bytes: The ciphertext
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
    
    def decrypt(self, ciphertext, key=None):
        """
        Decrypt ciphertext using the Feistel cipher.
        
        Args:
            ciphertext (bytes): The ciphertext to decrypt
            key (bytes, optional): The decryption key (uses sbox if None)
            
        Returns:
            bytes: The plaintext
        """
        # Extract IV
        iv = ciphertext[:self.block_size]
        ciphertext = ciphertext[self.block_size:]
        
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
            plaintext_block = bytearray(self.block_size)
            for i in range(self.block_size):
                plaintext_block[i] = decrypted_block[i] ^ prev_block[i]
                
            plaintext_blocks.append(bytes(plaintext_block))
            prev_block = block
            
        # Combine blocks and remove padding
        try:
            return self._unpad_data(b''.join(plaintext_blocks))
        except ValueError:
            # Handle padding errors gracefully
            return b''.join(plaintext_blocks)
            
    def get_cipher_info(self):
        """
        Get information about the cipher configuration.
        
        Returns:
            dict: Configuration information
        """
        return {
            "rounds": self.rounds,
            "block_size": self.block_size,
            "sbox_size": self.sbox_size
        }
