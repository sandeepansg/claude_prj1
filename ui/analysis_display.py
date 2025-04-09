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

        if not results:
            print("No semigroup test results available.")
            return

        success = all(r.get('verified', False) for r in results)
        for r in results:
            print(f"Test {r['test']}:")
            print(f"  Input value x (hex) = 0x{r['x']:X}")
            print(f"  T_s(x) (hex) = 0x{r['t_s_x']:X}")
            print(f"  T_r(T_s(x)) (hex) = 0x{r['t_r_t_s_x']:X}")
            print(f"  T_rs(x) (hex) = 0x{r['t_rs_x']:X}")
            print(f"  Result: {'✓ Verified' if r.get('verified', False) else '✗ Failed'}")
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

        if not results:
            print("No commutativity test results available.")
            return

        success = all(r.get('verified', False) for r in results)
        for r in results:
            print(f"Test {r['test']}:")
            print(f"  Input value x (hex) = 0x{r['x']:X}")
            print(f"  T_r(x) (hex) = 0x{r['t_r_x']:X}")
            print(f"  T_s(x) (hex) = 0x{r['t_s_x']:X}")
            print(f"  T_r(T_s(x)) (hex) = 0x{r['t_r_t_s_x']:X}")
            print(f"  T_s(T_r(x)) (hex) = 0x{r['t_s_t_r_x']:X}")
            print(f"  Result: {'✓ Verified' if r.get('verified', False) else '✗ Failed'}")
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
        
        # Handle case where properties or sbox might be None
        if not sbox or not properties:
            print("Error: S-box generation failed or produced invalid results.")
            return
            
        print(f"S-box size: {properties.get('box_size', len(sbox))} entries")
        
        # Show a sample of the S-box (first 16 entries)
        print("\nSample of S-box entries (first 16):")
        for i in range(min(16, len(sbox))):
            print(f"{i:3d} → {sbox[i]:3d}  ", end="")
            if (i + 1) % 4 == 0:
                print()
        print()
        
        # Show S-box properties
        print("\nS-box Cryptographic Properties:")
        print(f"- Bijective (one-to-one mapping): {'Yes' if properties.get('bijective', False) else 'No'}")
        print(f"- Fixed points: {properties.get('fixed_points', 'N/A')} out of {len(sbox)}")
        
        # Handle potentially missing avalanche properties
        avalanche_score = properties.get('avalanche_score', None)
        ideal_avalanche = properties.get('ideal_avalanche', None)
        if avalanche_score is not None and ideal_avalanche is not None:
            print(f"- Avalanche characteristic: {avalanche_score:.6f} "
                f"(ideal: {ideal_avalanche:.6f})")
        else:
            print("- Avalanche characteristic: Not evaluated")
        
        # Security score
        security_score = properties.get('security_score', 0)
        print(f"- Security score: {security_score:.4f} (higher is better)")
        
        # Evaluate S-box quality
        quality = "Excellent"
        if security_score < 0.8:
            quality = "Good"
        if security_score < 0.5:
            quality = "Fair"
        if security_score < 0.3:
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
        
        if ciphertext is None or decrypted is None:
            print("Error: Encryption or decryption process failed")
            return
        
        # Show the plaintext
        print(f"\nOriginal message: '{plaintext}'")
        
        # Show a preview of the ciphertext (base64 encoded)
        try:
            ciphertext_b64 = base64.b64encode(ciphertext).decode('ascii')
            preview_length = min(64, len(ciphertext_b64))
            print(f"Ciphertext (Base64, first {preview_length} chars): {ciphertext_b64[:preview_length]}")
        except Exception as e:
            print(f"Error encoding ciphertext to Base64: {str(e)}")
            print(f"Raw ciphertext length: {len(ciphertext)} bytes")
        
        # Show the decrypted text
        try:
            decoded_msg = decrypted if isinstance(decrypted, str) else decrypted.decode()
            print(f"Decrypted message: '{decoded_msg}'")
            
            # Show verification result
            success = plaintext == decoded_msg
            print(f"\nDecryption verification: {'✓ SUCCESS' if success else '✗ FAILED'}")
        except Exception as e:
            print(f"Error displaying decrypted text: {str(e)}")
            print("Decryption verification: ✗ FAILED")
            success = False
        
        # Display Feistel cipher security properties if available
        if feistel_properties:
            print("\nFeistel Cipher Security Analysis:")
            
            # Handle invertibility properties
            if 'invertibility' in feistel_properties:
                inv = feistel_properties['invertibility']
                print(f"- Invertibility: {inv.get('success_rate', 'N/A'):.4f} "
                    f"(avg time: {inv.get('avg_time', 'N/A'):.6f}s)")
            else:
                print("- Invertibility: Not evaluated")
                
            # Handle avalanche properties
            if 'avalanche' in feistel_properties:
                ava = feistel_properties['avalanche']
                print(f"- Avalanche effect: {ava.get('average', 'N/A'):.4f} "
                    f"(ideal: {ava.get('ideal', 'N/A'):.4f})")
            else:
                print("- Avalanche effect: Not evaluated")
                
            # Handle randomness properties
            if 'randomness' in feistel_properties:
                rand = feistel_properties['randomness']
                print(f"- Statistical randomness: {rand.get('bit_balance', 'N/A'):.4f}")
            else:
                print("- Statistical randomness: Not evaluated")
            
            # Overall score
            overall = feistel_properties.get('overall_score', 'N/A')
            if isinstance(overall, (int, float)):
                print(f"- Overall security score: {overall:.4f}")
            else:
                print(f"- Overall security score: {overall}")
        else:
            print("\nFeistel Cipher Security Analysis: Not available")
        
        if success:
            print("\nThe message was successfully encrypted and decrypted, demonstrating")
            print("the complete security pipeline: key exchange → S-box generation → encryption → decryption")
