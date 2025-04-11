"""
Analysis display for the Chebyshev cryptosystem.
Handles visualization and display of cryptographic properties and test results.
Includes comprehensive security analysis for IoT and digital twin applications.
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
            print("This property allows secure key exchange in IoT networks where")
            print("devices may have limited computational capabilities.")
        else:
            print(f"WARNING: The semigroup property failed in {total_tests - success_count} tests.")
            print("This could indicate a serious issue with the implementation.")
            print("IoT devices would be vulnerable if this property is not verified.")

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
            print("This property enables secure communication between IoT devices and")
            print("their digital twins without requiring synchronized key generation.")
        else:
            print(f"WARNING: The commutativity property failed in {total_tests - success_count} tests.")
            print("This could indicate a serious issue with the implementation.")
            print("Secure communication channels for digital twins would be compromised.")

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

        # Add context for IoT applications
        if len(sbox) <= 16:
            print("Small S-box size is optimized for resource-constrained IoT devices.")
        elif len(sbox) <= 64:
            print("Medium S-box size balances security and performance for typical IoT applications.")
        else:
            print("Large S-box size provides enhanced security for critical IoT systems and digital twins.")

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

        # Add IoT security context for fixed points
        fixed_points = properties.get('fixed_points', 0)
        if fixed_points > 0:
            fixed_percentage = (fixed_points / len(sbox)) * 100
            if fixed_percentage > 5:
                print(f"  Note: {fixed_percentage:.1f}% fixed points may reduce security for sensitive applications.")
            else:
                print(f"  Note: Fixed point percentage ({fixed_percentage:.1f}%) is acceptable for IoT security.")

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

            # Add IoT context for avalanche effect
            if quality in ["Excellent", "Good"]:
                print("  This provides strong protection against side-channel attacks,")
                print("  which is crucial for exposed IoT devices in untrusted environments.")
            else:
                print("  Suboptimal avalanche effect may expose IoT devices to side-channel attacks.")
                print("  Consider regenerating the S-box for improved security.")
        else:
            print("- Avalanche characteristic: Not evaluated")

        # Display SAC score if available
        sac_score = properties.get('sac_score', None)
        if sac_score is not None:
            print(f"- Strict Avalanche Criterion (SAC): {sac_score:.4f}")
            sac_quality = "Excellent" if sac_score > 0.45 else "Good" if sac_score > 0.4 else "Fair" if sac_score > 0.35 else "Poor"
            print(f"  SAC quality: {sac_quality} (ideal: 0.5)")

            # Add IoT context for SAC
            if sac_quality in ["Excellent", "Good"]:
                print("  Strong SAC ensures that small changes in IoT sensor data")
                print("  produce sufficiently different encrypted outputs.")
            else:
                print("  Weak SAC could allow attackers to infer patterns in IoT sensor data.")
                print("  This may be a concern for sensitive digital twin applications.")

        # Security score with detailed explanation
        security_score = properties.get('security_score', 0)
        print(f"- Security score: {security_score:.4f} (higher is better)")

        # Evaluate S-box quality with more granular ranges
        if security_score > 0.95:
            quality = "Excellent - Suitable for cryptographic use"
            print("  This S-box provides strong security for critical IoT applications and digital twins.")
        elif security_score > 0.8:
            quality = "Very Good - Strong security properties"
            print("  This S-box is well-suited for most IIoT applications and sensitive digital twins.")
        elif security_score > 0.65:
            quality = "Good - Acceptable for most uses"
            print("  This S-box is suitable for general purpose IoT communication.")
        elif security_score > 0.5:
            quality = "Fair - May need improvements for sensitive applications"
            print("  This S-box should be used with additional security measures for sensitive IoT data.")
        elif security_score > 0.3:
            quality = "Poor - Not recommended for security-critical operations"
            print("  Consider regenerating the S-box for IoT applications handling sensitive data.")
        else:
            quality = "Inadequate - Should be regenerated"
            print("  This S-box does not provide sufficient security for IoT applications.")

        print(f"- Overall quality: {quality}")
        print("\nThis S-box will be used for the Feistel cipher encryption.")

    @staticmethod
    def show_encryption_results(plaintext, ciphertext, decrypted, time_taken, feistel_properties, custom_key=None):
        """
        Display encryption and decryption results along with Feistel properties analysis.

        Args:
            plaintext (str): Original plaintext message
            ciphertext (bytes): Encrypted message
            decrypted (str): Decrypted message
            time_taken (float): Time for encryption/decryption process
            feistel_properties (dict): Results of Feistel cipher security tests
            custom_key (int, optional): Custom key used for encryption if applicable
        """
        print("\n" + "-" * 80)
        print("Feistel Cipher Encryption/Decryption")
        print("-" * 80)
        print(f"Encryption/decryption completed in {time_taken:.4f} seconds")

        # Add context about the time taken for IoT applications
        if time_taken < 0.05:
            print("Excellent speed! Suitable for real-time IoT applications and digital twins.")
        elif time_taken < 0.2:
            print("Good performance. Suitable for most IoT devices and applications.")
        else:
            print("Performance may be slow for resource-constrained IoT devices.")
            print("Consider reducing rounds or block size for time-sensitive applications.")

        if ciphertext is None or decrypted is None:
            print("Error: Encryption or decryption process failed")
            return

        # Show the key information if a custom key was used
        if custom_key is not None:
            print(f"\nUsing custom encryption key: 0x{custom_key:X}")
            print(f"Key bit length: {custom_key.bit_length()} bits")

        # Show the plaintext
        print(f"\nOriginal message: '{plaintext}'")

        # Show a preview of the ciphertext (base64 encoded)
        try:
            ciphertext_b64 = base64.b64encode(ciphertext).decode('ascii')
            preview_length = min(64, len(ciphertext_b64))
            print(f"Ciphertext (Base64, first {preview_length} chars): {ciphertext_b64[:preview_length]}")
            print(f"Full ciphertext length: {len(ciphertext)} bytes")

            # Add IoT context for message size
            overhead_ratio = len(ciphertext) / len(plaintext) if len(plaintext) > 0 else 0
            if overhead_ratio > 0:
                print(f"Encryption overhead: {overhead_ratio:.2f}x original size")
                if overhead_ratio > 1.5:
                    print("Note: High overhead may impact bandwidth in constrained IoT networks.")
                else:
                    print("Low overhead is suitable for bandwidth-constrained IoT networks.")
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

            if not success:
                print("WARNING: Decryption failed! This indicates a serious implementation issue.")
                print("Digital twin data integrity would be compromised.")
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

                    # Add IoT context for invertibility
                    if inv_quality == "Excellent":
                        print("  Perfect invertibility ensures reliable recovery of IoT data.")
                    elif inv_quality == "Good":
                        print("  Near-perfect invertibility is suitable for most IoT applications.")
                    else:
                        print("  Poor invertibility may result in data loss for digital twins.")
                else:
                    print(f"- Invertibility: {success_rate}")

                if isinstance(avg_time, (int, float)):
                    print(f"  Average time: {avg_time:.6f}s over {tests} tests")

                    # Add context for decrypt time
                    if avg_time < 0.01:
                        print("  Excellent decryption speed for real-time IoT applications.")
                    elif avg_time < 0.05:
                        print("  Good decryption speed suitable for most IoT devices.")
                    else:
                        print("  Decryption speed may be slow for time-sensitive IoT applications.")
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

                    # Add context for IoT security
                    if ava_quality in ["Excellent", "Good"]:
                        print("  Strong avalanche effect protects against side-channel attacks on IoT devices.")
                    else:
                        print("  Weak avalanche effect may expose patterns in IoT data.")

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

                    # Add IoT context for randomness
                    if rand_quality in ["Excellent", "Good"]:
                        print("  Strong randomness prevents statistical attacks on IoT communications.")
                    else:
                        print("  Weak randomness may allow pattern analysis in IoT data streams.")

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
                    print(f"- Overall security score: {overall:.4f} ({quality})")
                    print("  This configuration provides strong security for critical IoT applications and digital twins.")
                elif overall > 0.9:
                    quality = "Very Good - Strong security"
                    print(f"- Overall security score: {overall:.4f} ({quality})")
                    print("  This configuration is well-suited for IIoT applications and sensitive digital twins.")
                elif overall > 0.8:
                    quality = "Good - Adequate security"
                    print(f"- Overall security score: {overall:.4f} ({quality})")
                    print("  This configuration is suitable for general purpose IoT communication.")
                elif overall > 0.7:
                    quality = "Fair - May need improvements"
                    print(f"- Overall security score: {overall:.4f} ({quality})")
                    print("  Consider increasing rounds or improving S-box for sensitive IoT applications.")
                else:
                    quality = "Poor - Security concerns"
                    print(f"- Overall security score: {overall:.4f} ({quality})")
                    print("  This configuration may not provide adequate security for sensitive IoT data.")
            else:
                print(f"- Overall security score: {overall}")
        else:
            print("\nFeistel Cipher Security Analysis: Not available")

        if success:
            print("\nThe message was successfully encrypted and decrypted, demonstrating")
            print("the complete security pipeline: key exchange → S-box generation → encryption → decryption")
            print("This system is ready for deployment in IoT networks and digital twin applications.")