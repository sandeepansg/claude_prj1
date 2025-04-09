"""
User interface for the Chebyshev cryptosystem.
"""
import base64
from chebyshev.security import SecurityParams


class UserInterface:
    """Handles all user interaction and display."""

    @staticmethod
    def get_private_key_length():
        """Get private key length from user input."""
        while True:
            private_input = input(f"Enter private key length in bits [default={SecurityParams.DEFAULT_PRIVATE_BITS}]: ")
            if not private_input.strip():
                return None  # Use default

            try:
                private_bits = int(private_input)
                if private_bits >= SecurityParams.MIN_PRIVATE_BITS:
                    return private_bits
                print(f"Error: Private key must be at least {SecurityParams.MIN_PRIVATE_BITS} bits for security")
            except ValueError:
                print("Please enter a valid number")

    @staticmethod
    def get_feistel_params():
        """Get Feistel cipher parameters from user input."""
        print("\nFeistel Cipher Configuration")
        print("-" * 30)
        
        # Get rounds
        while True:
            rounds_input = input(f"Enter number of Feistel rounds [default={SecurityParams.DEFAULT_FEISTEL_ROUNDS}]: ")
            if not rounds_input.strip():
                rounds = None  # Use default
                break
                
            try:
                rounds = int(rounds_input)
                if rounds >= SecurityParams.MIN_FEISTEL_ROUNDS:
                    break
                print(f"Error: Number of rounds must be at least {SecurityParams.MIN_FEISTEL_ROUNDS} for security")
            except ValueError:
                print("Please enter a valid number")
                
        # Get block size
        while True:
            block_input = input(f"Enter block size in bytes [default={SecurityParams.DEFAULT_BLOCK_SIZE}]: ")
            if not block_input.strip():
                block_size = None  # Use default
                break
                
            try:
                block_size = int(block_input)
                if block_size >= SecurityParams.MIN_BLOCK_SIZE:
                    break
                print(f"Error: Block size must be at least {SecurityParams.MIN_BLOCK_SIZE} bytes for security")
            except ValueError:
                print("Please enter a valid number")
                
        return rounds, block_size
        
    @staticmethod
    def get_sbox_params():
        """Get S-box parameters from user input."""
        print("\nS-Box Configuration")
        print("-" * 30)
        
        while True:
            size_input = input(f"Enter S-box size [default={SecurityParams.DEFAULT_SBOX_SIZE}]: ")
            if not size_input.strip():
                return None  # Use default
                
            try:
                box_size = int(size_input)
                if box_size >= SecurityParams.MIN_SBOX_SIZE:
                    return box_size
                print(f"Error: S-box size must be at least {SecurityParams.MIN_SBOX_SIZE} for security")
            except ValueError:
                print("Please enter a valid number")

    @staticmethod
    def get_entropy():
        """Get optional entropy for key generation."""
        return input("Enter text for additional entropy (optional): ")

    @staticmethod
    def get_sample_message():
        """Get a sample message to encrypt."""
        default_message = "This is a secure message exchanged using Chebyshev polynomials!"
        message = input(f"Enter a message to encrypt [default: '{default_message}']: ")
        return message.strip() if message.strip() else default_message

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

    @staticmethod
    def show_semigroup_test(results):
        """Display detailed semigroup property test results."""
        print("\n" + "-" * 80)
        print("Semigroup Property Verification: T_r(T_s(x)) = T_{r*s}(x) mod q")
        print("-" * 80)

        success = all(r['verified'] for r in results)
        for r in results:
            print(f"Test {r['test']}:")
            print(f"  Input value x (hex) = 0x{r['x']:X}")
            print(f"  T_s(x) (hex) = 0x{r['t_s_x']:X}")
            print(f"  T_r(T_s(x)) (hex) = 0x{r['t_r_t_s_x']:X}")
            print(f"  T_rs(x) (hex) = 0x{r['t_rs_x']:X}")
            print(f"  Result: {'✓ Verified' if r['verified'] else '✗ Failed'}")
            print()

        print(f"Semigroup property: {'✓ VERIFIED' if success else '✗ FAILED'} for all tests")
        if success:
            print("The composition property T_r(T_s(x)) = T_{r*s}(x) holds, which is")
            print("essential for the security of the key exchange protocol.")

    @staticmethod
    def show_commutative_test(results):
        """Display detailed commutativity property test results."""
        print("\n" + "-" * 80)
        print("Commutativity Property Verification: T_r(T_s(x)) = T_s(T_r(x)) mod q")
        print("-" * 80)

        success = all(r['verified'] for r in results)
        for r in results:
            print(f"Test {r['test']}:")
            print(f"  Input value x (hex) = 0x{r['x']:X}")
            print(f"  T_r(x) (hex) = 0x{r['t_r_x']:X}")
            print(f"  T_s(x) (hex) = 0x{r['t_s_x']:X}")
            print(f"  T_r(T_s(x)) (hex) = 0x{r['t_r_t_s_x']:X}")
            print(f"  T_s(T_r(x)) (hex) = 0x{r['t_s_t_r_x']:X}")
            print(f"  Result: {'✓ Verified' if r['verified'] else '✗ Failed'}")
            print()

        print(f"Commutativity property: {'✓ VERIFIED' if success else '✗ FAILED'} for all tests")
        if success:
            print("The commutativity property T_r(T_s(x)) = T_s(T_r(x)) holds, which is")
            print("essential for the security of the key exchange protocol.")

    @staticmethod
    def show_sbox_info(sbox, properties, time_taken):
        """Display information about the generated S-box."""
        print("\n" + "-" * 80)
        print("S-box Generation and Analysis")
        print("-" * 80)
        print(f"S-box generated in {time_taken:.4f} seconds")
        print(f"S-box size: {properties['box_size']} entries")
        
        # Show a sample of the S-box (first 16 entries)
        print("\nSample of S-box entries (first 16):")
        for i in range(min(16, len(sbox))):
            print(f"{i:3d} → {sbox[i]:3d}  ", end="")
            if (i + 1) % 4 == 0:
                print()
        print()
        
        # Show S-box properties
        print("\nS-box Cryptographic Properties:")
        print(f"- Bijective (one-to-one mapping): {'Yes' if properties['bijective'] else 'No'}")
        print(f"- Fixed points: {properties['fixed_points']} out of {len(sbox)}")
        print(f"- Avalanche characteristic: {properties['avalanche_score']:.6f} "
              f"(ideal: {properties['ideal_avalanche']:.6f})")
        print(f"- Security score: {properties['security_score']:.4f} (higher is better)")
        
        # Evaluate S-box quality
        quality = "Excellent"
        if properties['security_score'] < 0.8:
            quality = "Good"
        if properties['security_score'] < 0.5:
            quality = "Fair"
        if properties['security_score'] < 0.3:
            quality = "Poor"
            
        print(f"- Overall quality: {quality}")
        print("\nThis S-box will be used for the Feistel cipher encryption.")

    @staticmethod
    def show_encryption_results(plaintext, ciphertext, decrypted, time_taken):
        """Display encryption and decryption results."""
        print("\n" + "-" * 80)
        print("Feistel Cipher Encryption/Decryption")
        print("-" * 80)
        print(f"Encryption/decryption completed in {time_taken:.4f} seconds")
        
        # Show the plaintext
        print(f"\nOriginal message: '{plaintext}'")
        
        # Show a preview of the ciphertext (base64 encoded)
        ciphertext_b64 = base64.b64encode(ciphertext).decode('ascii')
        preview_length = min(64, len(ciphertext_b64))
        print(f"Ciphertext (Base64, first {preview_length} chars): {ciphertext_b64[:preview_length]}")
        
        # Show the decrypted text
        print(f"Decrypted message: '{decrypted}'")
        
        # Show verification result
        success = plaintext == decrypted
        print(f"\nDecryption verification: {'✓ SUCCESS' if success else '✗ FAILED'}")
        if success:
            print("The message was successfully encrypted and decrypted, demonstrating")
            print("the complete security pipeline: key exchange → S-box generation → encryption → decryption")
