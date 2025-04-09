"""
Display handler for the Chebyshev cryptosystem.
Responsible for showing information to the user.
"""
import base64
from chebyshev.security import SecurityParams


class DisplayHandler:
    """Handles all display operations and formatting."""

    @staticmethod
    def show_header():
        """Display the application header."""
        print("=" * 80)
        print("Secure Chebyshev Polynomial Diffie-Hellman Key Exchange with Feistel Cipher")
        print("=" * 80)
        print("All security parameters will be automatically determined based on private key length")
        print(f"Default private key length: {SecurityParams.DEFAULT_PRIVATE_BITS} bits")
        print("You can customize Feistel cipher parameters and S-box size while maintaining security")

    @staticmethod
    def show_param_info(params):
        """Display derived security parameters."""
        print("\nAutomatically determined security parameters:")
        print(f"- Private key: {params['private_bits']} bits")
        print(f"- Prime modulus: {params['prime_bits']} bits")
        print(f"- Public parameter: {params['param_bits']} bits (exactly 1 bit less than prime)")
        print(f"- Public key: {params['public_bits']} bits")

    @staticmethod
    def show_system_info(system_info, init_time):
        """Display system initialization information."""
        print(f"\nSystem initialized in {init_time:.4f} seconds:")
        print(f"- Prime modulus (hex) = 0x{system_info['mod']:X} ({system_info['mod_bits']} bits)")
        print(f"- Public parameter (hex) = 0x{system_info['param']:X} ({system_info['param_bits']} bits)")
        print(f"- Private key size = {system_info['private_bits']} bits")
        print(f"- Public key size = {system_info['public_bits']} bits")

    @staticmethod
    def show_feistel_params(cipher_info):
        """Display Feistel cipher parameters."""
        print("\nFeistel Cipher Parameters:")
        print(f"- Number of rounds: {cipher_info['rounds']} rounds")
        print(f"- Block size: {cipher_info['block_size']} bytes")
        print(f"- S-box size: {cipher_info['sbox_size']} entries")

    @staticmethod
    def show_exchange_results(results, time_taken):
        """Display key exchange results."""
        print("\n" + "-" * 80)
        print("Key Exchange Results")
        print("-" * 80)

        # Show Alice's keys
        print(f"Alice private key (hex): 0x{results['alice_private']:X} ({results['alice_private'].bit_length()} bits)")
        print(f"Alice raw public key (hex): 0x{results['alice_raw_public']:X}")
        print(f"Alice formatted public key (hex): 0x{results['alice_public']:X} ({results['alice_public'].bit_length()} bits)")

        # Show Bob's keys
        print(f"Bob private key (hex): 0x{results['bob_private']:X} ({results['bob_private'].bit_length()} bits)")
        print(f"Bob raw public key (hex): 0x{results['bob_raw_public']:X}")
        print(f"Bob formatted public key (hex): 0x{results['bob_public']:X} ({results['bob_public'].bit_length()} bits)")

        # Show shared secrets
        print(f"\nAlice shared secret (hex): 0x{results['alice_shared']:X}")
        print(f"Bob shared secret (hex): 0x{results['bob_shared']:X}")
        print(f"\nShared secrets match: {'Yes' if results['match'] else 'No'}")
        print(f"Exchange completed in {time_taken:.4f} seconds")
