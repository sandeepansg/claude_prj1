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
        print("You can also enter private keys manually to simulate key exchange between separate instances")
        print("This implementation is optimized for IoT, IIoT, and digital twin security applications")

    @staticmethod
    def show_param_info(params):
        """Display derived security parameters."""
        print("\nAutomatically determined security parameters:")
        print(f"- Private key: {params['private_bits']} bits")
        print(f"- Prime modulus: {params['prime_bits']} bits")
        print(f"- Public parameter: {params['param_bits']} bits (exactly 1 bit less than prime)")
        print(f"- Public key: {params['public_bits']} bits")
        print("\nThese parameters provide a balance between security and performance,")
        print("suitable for resource-constrained IoT devices and real-time digital twin applications.")

    @staticmethod
    def show_system_info(system_info, init_time):
        """Display system initialization information."""
        print(f"\nSystem initialized in {init_time:.4f} seconds:")
        print(f"- Prime modulus (hex) = 0x{system_info['mod']:X} ({system_info['mod_bits']} bits)")
        print(f"- Public parameter (hex) = 0x{system_info['param']:X} ({system_info['param_bits']} bits)")
        print(f"- Private key size = {system_info['private_bits']} bits")
        print(f"- Public key size = {system_info['public_bits']} bits")

        # Add performance commentary for IoT applications
        if system_info['private_bits'] <= 32:
            print("\nNote: Current configuration is optimized for resource-constrained IoT devices.")
        elif system_info['private_bits'] <= 64:
            print("\nNote: Current configuration provides a good balance between security and performance.")
        else:
            print("\nNote: Current configuration prioritizes security over performance.")
            print("Consider reducing key size for resource-constrained IoT devices.")

    @staticmethod
    def show_feistel_params(cipher_info):
        """Display Feistel cipher parameters."""
        print("\nFeistel Cipher Parameters:")
        print(f"- Number of rounds: {cipher_info['rounds']} rounds")
        print(f"- Block size: {cipher_info['block_size']} bytes")
        print(f"- S-box size: {cipher_info['sbox_size']} entries")

        # Add recommendations based on parameters
        if cipher_info['rounds'] < 12:
            print("\nNote: Fewer rounds improves performance but may reduce security margin.")
            print("Recommended for frequently communicating IoT devices with strict latency requirements.")
        else:
            print("\nNote: Higher round count provides stronger security at the cost of performance.")
            print("Recommended for sensitive data or less frequent communications.")

        if cipher_info['block_size'] <= 8:
            print("\nSmall block size is suitable for sensor data and IoT telemetry.")
        else:
            print("\nLarger block size is suitable for digital twin synchronization and commands.")

    @staticmethod
    def show_exchange_results(results, time_taken, alice_b64=None, bob_b64=None):
        """Display key exchange results."""
        print("\n" + "-" * 80)
        print("Key Exchange Results")
        print("-" * 80)

        # Show Alice's keys
        alice_bits = results['alice_private'].bit_length()
        print(f"Alice private key (hex): 0x{results['alice_private']:X} ({alice_bits} bits)")
        if alice_b64:
            print(f"Alice private key (base64): {alice_b64}")
        print(f"Alice raw public key (hex): 0x{results['alice_raw_public']:X}")
        print(f"Alice formatted public key (hex): 0x{results['alice_public']:X} ({results['alice_public'].bit_length()} bits)")

        # Show Bob's keys
        bob_bits = results['bob_private'].bit_length()
        print(f"Bob private key (hex): 0x{results['bob_private']:X} ({bob_bits} bits)")
        if bob_b64:
            print(f"Bob private key (base64): {bob_b64}")
        print(f"Bob raw public key (hex): 0x{results['bob_raw_public']:X}")
        print(f"Bob formatted public key (hex): 0x{results['bob_public']:X} ({results['bob_public'].bit_length()} bits)")

        # Check if there was an error
        if 'error' in results:
            print(f"\nERROR: {results['error']}")
            print("Key exchange failed. Please try again with compatible keys.")
            return False

        # Show shared secrets
        print(f"\nAlice shared secret (hex): 0x{results['alice_shared']:X}")
        print(f"Bob shared secret (hex): 0x{results['bob_shared']:X}")
        print(f"\nShared secrets match: {'Yes' if results['match'] else 'No'}")
        print(f"Exchange completed in {time_taken:.4f} seconds")

        # Add performance analysis for IoT context
        if time_taken < 0.1:
            print("\nExcellent performance! Suitable for real-time IoT applications and digital twins.")
        elif time_taken < 0.5:
            print("\nGood performance. Suitable for most IoT devices and applications.")
        else:
            print("\nPerformance may be slow for some real-time applications.")
            print("Consider reducing key size or optimizing system parameters for IoT devices.")

        # Add security estimate
        shared_bits = results['alice_shared'].bit_length()
        print(f"\nShared secret entropy: ~{shared_bits} bits")

        if shared_bits >= 128:
            print("Security level: Strong (equivalent to AES-128 or better)")
        elif shared_bits >= 80:
            print("Security level: Moderate (suitable for most IoT applications)")
        else:
            print("Security level: Basic (may be sufficient for non-critical IoT applications)")

        return results['match']