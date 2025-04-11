"""
Security property testing for Chebyshev-based cryptosystems.
"""
import random
import time
import os


class SecurityTester:
    """Tests mathematical properties essential for security."""

    def __init__(self, dh_instance=None):
        self.dh = dh_instance
        self.cheby = dh_instance.cheby if dh_instance else None
        self.mod = dh_instance.mod if dh_instance else None
        
    def _validate_test_params(self, count, r, s):
        """Common validation for test parameters."""
        # Input validation
        if not isinstance(count, int) or count <= 0:
            raise ValueError("Test count must be a positive integer")

        if not all(isinstance(x, int) for x in [r, s]):
            raise TypeError("r and s must be integers")
            
        # Set reasonable limits
        count = min(count, 100)  # Prevent excessive computation

        # Validate r and s are within safe range
        if r <= 0 or s <= 0 or r >= self.mod or s >= self.mod:
            raise ValueError(f"r and s must be between 1 and {self.mod-1}")
            
        return count

    def test_semigroup(self, count, r, s):
        """Test semigroup property: T_r(T_s(x)) = T_{r*s}(x) mod q"""
        if not self.cheby:
            raise ValueError("DH instance required for polynomial tests")
            
        count = self._validate_test_params(count, r, s)
        
        results = []
        for i in range(count):
            x = random.randint(1, self.mod - 1)
            t_s_x = self.cheby.eval(s, x)
            t_r_t_s_x = self.cheby.eval(r, t_s_x)
            t_rs_x = self.cheby.eval(r * s, x)
            results.append({
                "test": i + 1,
                "x": x,
                "t_s_x": t_s_x,
                "t_r_t_s_x": t_r_t_s_x,
                "t_rs_x": t_rs_x,
                "verified": t_r_t_s_x == t_rs_x
            })
        return results

    def test_commutative(self, count, r, s):
        """Test commutativity: T_r(T_s(x)) = T_s(T_r(x)) mod q"""
        if not self.cheby:
            raise ValueError("DH instance required for polynomial tests")
            
        count = self._validate_test_params(count, r, s)
            
        results = []
        for i in range(count):
            x = random.randint(1, self.mod - 1)
            t_r_x = self.cheby.eval(r, x)
            t_s_t_r_x = self.cheby.eval(s, t_r_x)
            t_s_x = self.cheby.eval(s, x)
            t_r_t_s_x = self.cheby.eval(r, t_s_x)
            results.append({
                "test": i + 1,
                "x": x,
                "t_r_x": t_r_x,
                "t_s_x": t_s_x,
                "t_r_t_s_x": t_r_t_s_x,
                "t_s_t_r_x": t_s_t_r_x,
                "verified": t_r_t_s_x == t_s_t_r_x
            })
        return results
        
    def test_sbox_properties(self, sbox, test_samples=None):
        """
        Test cryptographic properties of the S-box.
        
        Args:
            sbox (list): The S-box to test
            test_samples (int): Number of samples for testing (optional)
            
        Returns:
            dict: Results of various cryptographic tests
        """
        box_size = len(sbox)
        
        # Set reasonable sample size based on box size
        if test_samples is None:
            # Default number of samples
            sample_size = min(box_size, 256)
        else:
            # Use provided sample size, with bounds
            sample_size = min(max(16, test_samples), box_size)
        
        # Check for bijection (one-to-one mapping)
        is_bijective = len(set(sbox)) == box_size
        
        # Check for fixed points
        fixed_points = sum(1 for i in range(box_size) if sbox[i] == i)
        
        # Calculate nonlinearity metrics with consistent sample size
        differences = []
        # Only test a limited number of difference patterns
        test_patterns = min(sample_size, box_size)
        
        for i in range(1, test_patterns):
            xor_differences = []
            # Sample a limited number of input values
            for x in range(0, sample_size):
                input_diff = x ^ i  # XOR difference in input
                # Ensure input_diff is within S-box range
                input_diff = input_diff % box_size
                output_diff = sbox[x % box_size] ^ sbox[input_diff]  # XOR difference in output
                xor_differences.append(output_diff)
            # Count most common output difference
            if xor_differences:
                max_count = max(xor_differences.count(d) for d in set(xor_differences))
                differences.append(max_count / len(xor_differences))
        
        avalanche_score = max(differences) if differences else 1.0
        
        # Calculate SAC (Strict Avalanche Criterion) with consistent approach
        sac_score = 0
        if box_size <= 256:  # Only calculate for reasonably sized S-boxes
            sac_total = 0
            sac_count = 0
            test_bits = min(16, box_size)
            test_inputs = min(16, box_size)
            
            for i in range(test_bits):  # Test a subset of bits
                for j in range(test_inputs):  # Test a subset of inputs
                    flipped_j = j ^ (1 << i % 8)  # Flip one bit
                    if flipped_j >= box_size:
                        continue
                    hamming_distance = bin(sbox[j] ^ sbox[flipped_j]).count('1')
                    sac_total += hamming_distance
                    sac_count += 1
            if sac_count > 0:
                sac_score = sac_total / (sac_count * 8)  # Normalize to [0,1]
        
        return {
            "bijective": is_bijective,
            "fixed_points": fixed_points,
            "box_size": box_size,
            "avalanche_score": avalanche_score,
            "ideal_avalanche": 1/sample_size,
            "sac_score": sac_score,
            "sample_size": sample_size,
            "test_patterns": test_patterns,
            "security_score": 1 - (avalanche_score - 1/sample_size) if avalanche_score >= 1/sample_size else 0.99
        }
        
    def test_feistel_properties(self, cipher, iterations=50):
        """
        Test the cryptographic properties of a Feistel cipher.
        
        Args:
            cipher (FeistelCipher): The cipher instance to test
            iterations (int): Number of test iterations
            
        Returns:
            dict: Results of various tests
        """
        # Validate iterations and set reasonable limit
        if not isinstance(iterations, int) or iterations <= 0:
            raise ValueError("Iterations must be a positive integer")
        iterations = min(iterations, 100)  # Prevent excessive computation
        
        start_time = time.time()
        results = {}
        
        # 1. Test invertibility (basic property)
        invertibility_success = 0
        invertibility_times = []
        
        for i in range(iterations):
            # Random message length between 1 and 100 bytes
            msg_len = random.randint(1, 100)
            message = os.urandom(msg_len)
            
            start = time.time()
            ciphertext = cipher.encrypt(message)
            decrypted = cipher.decrypt(ciphertext)
            invertibility_times.append(time.time() - start)
            
            if message == decrypted:
                invertibility_success += 1
                
        results["invertibility"] = {
            "success_rate": invertibility_success / iterations,
            "avg_time": sum(invertibility_times) / len(invertibility_times) if invertibility_times else 0,
            "tests": iterations
        }
        
        # 2. Test avalanche effect - use consistent sample size
        avalanche_tests = min(20, iterations)
        avalanche_scores = []
        
        for i in range(avalanche_tests):
            # Generate random message (8 bytes for simplicity)
            message = os.urandom(8)
            cipher1 = cipher.encrypt(message)
            
            # Flip one random bit in the message
            mod_message = bytearray(message)
            byte_to_change = random.randint(0, len(message)-1)
            bit_to_change = random.randint(0, 7)
            mod_message[byte_to_change] ^= (1 << bit_to_change)
            cipher2 = cipher.encrypt(bytes(mod_message))
            
            # Count differing bits
            diff_bits = 0
            for b1, b2 in zip(cipher1, cipher2):
                diff_bits += bin(b1 ^ b2).count('1')
                
            # Ideal: 50% of bits changed
            total_bits = len(cipher1) * 8
            avalanche_scores.append(diff_bits / total_bits)
            
        avg_avalanche = sum(avalanche_scores) / len(avalanche_scores) if avalanche_scores else 0
        ideal_avalanche = 0.5  # 50% bit flip is ideal
        
        results["avalanche"] = {
            "average": avg_avalanche,
            "ideal": ideal_avalanche,
            "quality_score": 1 - abs(avg_avalanche - ideal_avalanche) * 2,  # Scale to [0,1]
            "tests": avalanche_tests
        }
        
        # 3. Test statistical randomness - use consistent sample size
        randomness_tests = min(10, iterations)
        bit_counts = [0, 0]  # count of 0s and 1s
        total_samples = 0
        
        for i in range(randomness_tests):
            # Generate random message
            message = b"X" * 1000  # Fixed message to check randomness of encryption
            ciphertext = cipher.encrypt(message)
            
            # Count bits
            for byte in ciphertext:
                for j in range(8):
                    bit = (byte >> j) & 1
                    bit_counts[bit] += 1
                    total_samples += 1
                    
        bit_balance = min(bit_counts) / max(bit_counts) if max(bit_counts) > 0 else 0
        results["randomness"] = {
            "bit_balance": bit_balance,  # Closer to 1.0 is better
            "quality_score": bit_balance,  # Direct mapping to [0,1]
            "tests": randomness_tests,
            "bits_analyzed": total_samples
        }
        
        # Calculate overall score (weighted average)
        overall_score = (
            results["invertibility"]["success_rate"] * 0.4 +
            results["avalanche"]["quality_score"] * 0.4 +
            results["randomness"]["quality_score"] * 0.2
        )
        
        results["overall_score"] = overall_score
        results["time_taken"] = time.time() - start_time
        results["total_tests"] = iterations
        
        return results
