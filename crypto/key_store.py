"""
Key store module for the Chebyshev cryptosystem.
Handles saving and loading of private keys to/from files.
"""
import os
import json
import base64
import hashlib
from datetime import datetime


class KeyStore:
    """Handles storage and retrieval of private keys."""
    
    DEFAULT_KEYS_DIR = "keys"
    
    @staticmethod
    def ensure_keys_directory():
        """Ensure the keys directory exists."""
        if not os.path.exists(KeyStore.DEFAULT_KEYS_DIR):
            os.makedirs(KeyStore.DEFAULT_KEYS_DIR)
    
    @staticmethod
    def generate_key_filename(owner_name, timestamp=None):
        """Generate a filename for a key based on owner name and timestamp."""
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create a safe filename
        safe_name = "".join(c if c.isalnum() else "_" for c in owner_name.lower())
        return f"{safe_name}_{timestamp}.key"
    
    @staticmethod
    def save_private_key(private_key, owner_name, additional_info=None, timestamp=None):
        """
        Save a private key to a file.
        
        Args:
            private_key (int): The private key to save
            owner_name (str): Name of the key owner (e.g., "alice", "bob")
            additional_info (dict, optional): Additional metadata to save with the key
            timestamp (str, optional): Custom timestamp, will generate one if not provided
            
        Returns:
            str: The filename where the key was saved
        """
        KeyStore.ensure_keys_directory()
        
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        filename = KeyStore.generate_key_filename(owner_name, timestamp)
        filepath = os.path.join(KeyStore.DEFAULT_KEYS_DIR, filename)
        
        # Encode private key as hex string
        key_hex = hex(private_key)
        
        # Create key file data structure
        key_data = {
            "owner": owner_name,
            "created": timestamp,
            "private_key": key_hex,
            "key_fingerprint": KeyStore.generate_fingerprint(private_key)
        }
        
        # Add any additional info
        if additional_info and isinstance(additional_info, dict):
            key_data.update(additional_info)
        
        # Write to file
        with open(filepath, 'w') as f:
            json.dump(key_data, f, indent=2)
        
        return filepath
    
    @staticmethod
    def load_private_key(filepath_or_filename):
        """
        Load a private key from a file.
        
        Args:
            filepath_or_filename (str): Path to the key file or just the filename
            
        Returns:
            tuple: (private_key, owner_name, additional_metadata)
        """
        # Handle case where just filename is provided
        if not os.path.dirname(filepath_or_filename):
            filepath = os.path.join(KeyStore.DEFAULT_KEYS_DIR, filepath_or_filename)
        else:
            filepath = filepath_or_filename
        
        # Check if file exists
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Key file not found: {filepath}")
        
        # Read key data
        with open(filepath, 'r') as f:
            key_data = json.load(f)
        
        # Extract private key
        private_key_hex = key_data.pop("private_key")
        owner = key_data.pop("owner")
        
        # Convert hex string to integer
        private_key = int(private_key_hex, 16)
        
        # Verify fingerprint to ensure integrity
        stored_fingerprint = key_data.get("key_fingerprint")
        if stored_fingerprint:
            calculated_fingerprint = KeyStore.generate_fingerprint(private_key)
            if calculated_fingerprint != stored_fingerprint:
                raise ValueError("Key integrity check failed: fingerprint mismatch")
        
        return private_key, owner, key_data
    
    @staticmethod
    def list_available_keys():
        """
        List all available key files in the keys directory.
        
        Returns:
            list: List of key files with metadata
        """
        KeyStore.ensure_keys_directory()
        
        key_files = []
        for filename in os.listdir(KeyStore.DEFAULT_KEYS_DIR):
            if filename.endswith('.key'):
                filepath = os.path.join(KeyStore.DEFAULT_KEYS_DIR, filename)
                try:
                    with open(filepath, 'r') as f:
                        key_data = json.load(f)
                    
                    key_files.append({
                        "filename": filename,
                        "owner": key_data.get("owner", "unknown"),
                        "created": key_data.get("created", "unknown"),
                        "fingerprint": key_data.get("key_fingerprint", "unknown")
                    })
                except Exception as e:
                    # Skip files that can't be parsed
                    continue
        
        return key_files
    
    @staticmethod
    def generate_fingerprint(private_key):
        """
        Generate a fingerprint for a private key for verification purposes.
        
        Args:
            private_key (int): The private key
            
        Returns:
            str: Fingerprint string
        """
        # Convert private key to bytes
        key_bytes = str(private_key).encode('utf-8')
        
        # Generate SHA-256 hash
        key_hash = hashlib.sha256(key_bytes).digest()
        
        # Return base64 encoded first 16 bytes for a shorter fingerprint
        return base64.b64encode(key_hash[:16]).decode('ascii')
