"""
Analysis display for the Chebyshev cryptosystem.
Handles visualization and display of cryptographic properties and test results.
"""
import base64


class AnalysisDisplay:
    """Handles display of analysis and testing results."""

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
    def show_encryption_results(plaintext, ciphertext, decrypted, time_taken, feistel_properties):
        """
        Display encryption and decryption results along with Feistel properties analysis.
        
        Args:
            plaintext (str): Original plaintext message
            ciphertext (bytes): Encrypted message
            decrypted (str): Decrypted message
            time_taken (float): Time for encryption/decryption process
            feistel_properties (dict): Results of Feistel cipher security tests
        """
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
        
        # Display Feistel cipher security properties
        print("\nFeistel Cipher Security Analysis:")
        print(f"- Invertibility: {feistel_properties['invertibility']['success_rate']:.4f} "
              f"(avg time: {feistel_properties['invertibility']['avg_time']:.6f}s)")
        print(f"- Avalanche effect: {feistel_properties['avalanche']['average']:.4f} "
              f"(ideal: {feistel_properties['avalanche']['ideal']:.4f})")
        print(f"- Statistical randomness: {feistel_properties['randomness']['bit_balance']:.4f}")
        print(f"- Overall security score: {feistel_properties['overall_score']:.4f}")
        
        if success:
            print("\nThe message was successfully encrypted and decrypted, demonstrating")
            print("the complete security pipeline: key exchange → S-box generation → encryption → decryption")
