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

        # Display a summary first with total tests
        total_tests = len(results)
        success_count = sum(1 for r in results if r.get('verified', False))
        print(f"Total tests: {total_tests}")
        print(f"Successful tests: {success_count}")
        print(f"Success rate: {success_count/total_tests:.2%}")
        print()

        # Only show detailed results for up to 5 tests to avoid overwhelming the user
        display_count = min(5, len(results))
        if display_count < len(results):
            print(f"Showing first {display_count} of {len(results)} test results:")
        
        for i, r in enumerate(results[:display_count]):
            print(f"Test {r['test']}:")
            print(f"  Input value x (hex) = 0x{r['x']:X}")
            print(f"  T_s(x) (hex) = 0x{r['t_s_x']:X}")
            print(f"  T_r(T_s(x)) (hex) = 0x{r['t_r_t_s_x']:X}")
            print(f"  T_rs(x) (hex) = 0x{r['t_rs_x']:X}")
            print(f"  Result: {'✓ Verified' if r.get('verified', False) else '✗ Failed'}")
            print()

        success = all(r.get('verified', False) for r in results)
        print(f"Semigroup property: {'✓ VERIFIED' if success else '✗ FAILED'} for all {len(results)} tests")
        if success:
            print("The composition property T_r(T_s(x)) = T_{r*s}(x) holds, which is")
            print("essential for the security of the key exchange protocol.")
        else:
            print(f"WARNING: The semigroup property failed in {total_tests - success_count} tests.")

    @staticmethod
    def show_commutative_test(results):
        """Display detailed commutativity property test results."""
        print("\n" + "-" * 80)
        print("Commutativity Property Verification: T_r(T_s(x)) = T_s(T_r(x)) mod q")
        print("-" * 80)

        if not results:
            print("No commutativity test results available.")
            return

        # Display a summary first with total tests
        total_tests = len(results)
        success_count = sum(1 for r in results if r.get('verified', False))
        print(f"Total tests: {total_tests}")
        print(f"Successful tests: {success_count}")
        print(f"Success rate: {success_count/total_tests:.2%}")
        print()

        # Only show detailed results for up to 5 tests to avoid overwhelming the user
        display_count = min(5, len(results))
        if display_count < len(results):
            print(f"Showing first {display_count} of {len(results)} test results:")
            
        for i, r in enumerate(results[:display_count]):
            print(f"Test {r['test']}:")
            print(f"  Input value x (hex) = 0x{r['x']:X}")
            print(f"  T_r(x) (hex) = 0x{r['t_r_x']:X}")
            print(f"  T_s(x) (hex) = 0x{r['t_s_x']:X}")
            print(f"  T_r(T_s(x)) (hex) = 0x{r['t_r_t_s_x']:X}")
            print(f"  T_s(T_r(x)) (hex) = 0x{r['t_s_t_r_x']:X}")
            print(f"  Result: {'✓ Verified' if r.get('verified', False) else '✗ Failed'}")
            print()

        success = all(r.get('verified', False) for r in results)
        print(f"Commutativity property: {'✓ VERIFIED' if success else '✗ FAILED'} for all {len(results)} tests")
        if success:
            print("The commutativity property T_r(T_s(x)) = T_s(T_r(x)) holds, which is")
            print("essential for the security of the key exchange protocol.")
        else:
            print(f"WARNING: The commutativity property failed in {total_tests - success_count} tests.")

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
        
        # Show S-box properties with consistent output
        print("\nS-box Cryptographic Properties:")
        print(f"- Bijective (one-to-one mapping): {'Yes' if properties.get('bijective', False) else 'No'}")
        print(f"- Fixed points: {properties.get('fixed_points', 'N/A')} out of {len(sbox)}")
        
        # Display detailed testing information
        print(f"- Tests performed: {properties.get('sample_size', 'N/A')} samples")
        print(f"- Test patterns analyzed: {properties.get('test_patterns', 'N/A')}")
        
        # Handle avalanche properties
        avalanche_score = properties.get('avalanche_score', None)
        ideal_avalanche = properties.get('ideal_avalanche', None)
        if avalanche_score is not None and ideal_avalanche is not None:
            print(f"- Avalanche characteristic: {avalanche_score:.6f} "
                f"(ideal: {ideal_avalanche:.6f})")
            diff = abs(avalanche_score - ideal_avalanche)
            quality = "Excellent" if diff < 0.01 else "Good" if diff < 0.05 else "Fair" if diff < 0.1 else "Poor"
            print(f"  Avalanche quality: {quality} (difference from ideal: {diff:.6f})")
        else:
            print("- Avalanche characteristic: Not evaluated")
        
        # Display SAC score if available
        sac_score = properties.get('sac_score', None)
        if sac_score is not None:
            print(f"- Strict Avalanche Criterion (SAC): {sac_score:.4f}")
            sac_quality = "Excellent" if sac_score > 0.45 else "Good" if sac_score > 0.4 else "Fair" if sac_score > 0.35 else "Poor"
            print(f"  SAC quality: {sac_quality} (ideal: 0.5)")
        
        # Security score with detailed explanation
        security_score = properties.get('security_score', 0)
        print(f"- Security score: {security_score:.4f} (higher is better)")
        
        # Evaluate S-box quality with more granular ranges
        if security_score > 0.95:
            quality = "Excellent - Suitable for cryptographic use"
        elif security_score > 0.8:
            quality = "Very Good - Strong security properties"
        elif security_score > 0.65:
            quality = "Good - Acceptable for most uses"
        elif security_score > 0.5:
            quality = "Fair - May need improvements for sensitive applications"
        elif security_score > 0.3:
            quality = "Poor - Not recommended for security-critical operations"
        else:
            quality = "Inadequate - Should be regenerated"
            
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
            print(f"Full ciphertext length: {len(ciphertext)} bytes")
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
            
            # Display test information
            total_tests = feistel_properties.get('total_tests', 'N/A')
            time_taken_tests = feistel_properties.get('time_taken', 'N/A')
            if isinstance(time_taken_tests, (int, float)):
                print(f"Performed {total_tests} tests in {time_taken_tests:.4f} seconds")
            else:
                print(f"Performed {total_tests} tests")
            
            # Handle invertibility properties
            if 'invertibility' in feistel_properties:
                inv = feistel_properties['invertibility']
                success_rate = inv.get('success_rate', 'N/A')
                avg_time = inv.get('avg_time', 'N/A')
                tests = inv.get('tests', 'N/A')
                
                if isinstance(success_rate, (int, float)):
                    inv_quality = "Excellent" if success_rate == 1.0 else "Good" if success_rate > 0.95 else "Poor"
                    print(f"- Invertibility: {success_rate:.4f} ({inv_quality})")
                else:
                    print(f"- Invertibility: {success_rate}")
                    
                if isinstance(avg_time, (int, float)):
                    print(f"  Average time: {avg_time:.6f}s over {tests} tests")
            else:
                print("- Invertibility: Not evaluated")
                
            # Handle avalanche properties
            if 'avalanche' in feistel_properties:
                ava = feistel_properties['avalanche']
                average = ava.get('average', 'N/A')
                ideal = ava.get('ideal', 'N/A')
                quality_score = ava.get('quality_score', 'N/A')
                tests = ava.get('tests', 'N/A')
                
                if isinstance(average, (int, float)) and isinstance(ideal, (int, float)):
                    diff = abs(average - ideal)
                    ava_quality = "Excellent" if diff < 0.05 else "Good" if diff < 0.1 else "Fair" if diff < 0.15 else "Poor"
                    print(f"- Avalanche effect: {average:.4f} (ideal: {ideal:.4f}, {ava_quality})")
                    if isinstance(quality_score, (int, float)):
                        print(f"  Quality score: {quality_score:.4f} over {tests} tests")
                else:
                    print(f"- Avalanche effect: {average}")
            else:
                print("- Avalanche effect: Not evaluated")
                
            # Handle randomness properties
            if 'randomness' in feistel_properties:
                rand = feistel_properties['randomness']
                bit_balance = rand.get('bit_balance', 'N/A')
                quality_score = rand.get('quality_score', 'N/A')
                tests = rand.get('tests', 'N/A')
                bits_analyzed = rand.get('bits_analyzed', 'N/A')
                
                if isinstance(bit_balance, (int, float)):
                    rand_quality = "Excellent" if bit_balance > 0.95 else "Good" if bit_balance > 0.9 else "Fair" if bit_balance > 0.8 else "Poor"
                    print(f"- Statistical randomness: {bit_balance:.4f} ({rand_quality})")
                    print(f"  Analyzed {bits_analyzed} bits over {tests} tests")
                else:
                    print(f"- Statistical randomness: {bit_balance}")
            else:
                print("- Statistical randomness: Not evaluated")
            
            # Overall score with qualitative assessment
            overall = feistel_properties.get('overall_score', 'N/A')
            if isinstance(overall, (int, float)):
                if overall > 0.95:
                    quality = "Excellent - Highly secure"
                elif overall > 0.9:
                    quality = "Very Good - Strong security"
                elif overall > 0.8:
                    quality = "Good - Adequate security"
                elif overall > 0.7:
                    quality = "Fair - May need improvements"
                else:
                    quality = "Poor - Security concerns"
                print(f"- Overall security score: {overall:.4f} ({quality})")
            else:
                print(f"- Overall security score: {overall}")
        else:
            print("\nFeistel Cipher Security Analysis: Not available")
        
        if success:
            print("\nThe message was successfully encrypted and decrypted, demonstrating")
            print("the complete security pipeline: key exchange → S-box generation → encryption → decryption")
