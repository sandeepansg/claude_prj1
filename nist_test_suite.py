"""
NIST Statistical Test Suite implementation for Chebyshev cryptosystem evaluation.

This module implements a subset of the NIST SP 800-22 statistical tests for 
randomness to evaluate the cryptographic strength of the Feistel cipher.
"""
import math
import numpy as np
from scipy import special
import random
import time
from typing import List, Dict, Tuple, Optional, Union


class NISTTester:
    """Implementation of key NIST SP 800-22 statistical tests for randomness."""

    def __init__(self, sequence=None):
        """
        Initialize the NIST tester.
        
        Args:
            sequence (bytes, optional): Binary sequence to test
        """
        self.sequence = sequence
        
    def set_sequence(self, sequence):
        """
        Set the binary sequence to test.
        
        Args:
            sequence (bytes): Binary sequence to test
        """
        self.sequence = sequence
        
    @staticmethod
    def _bits_to_int_array(data: bytes) -> np.ndarray:
        """
        Convert bytes to an array of bits (0s and 1s).
        
        Args:
            data: Input bytes
            
        Returns:
            numpy.ndarray: Array of 0s and 1s
        """
        result = []
        for byte in data:
            for i in range(8):
                result.append((byte >> i) & 1)
        return np.array(result)
        
    def frequency_test(self, sequence=None) -> Dict:
        """
        Performs the NIST Frequency (Monobit) Test.
        
        This test evaluates whether the number of 0s and 1s in the sequence
        is approximately the same, as would be expected for a truly random sequence.
        
        Args:
            sequence (bytes, optional): Sequence to test, uses self.sequence if None
            
        Returns:
            dict: Test results with p-value and success status
        """
        sequence = sequence if sequence is not None else self.sequence
        bits = self._bits_to_int_array(sequence)
        
        # Count 1s and transform to ±1
        s = 2 * bits - 1  # Transform 0 -> -1, 1 -> 1
        s_n = np.sum(s)
        
        # Calculate test statistic
        n = len(bits)
        s_obs = abs(s_n) / math.sqrt(n)
        
        # Calculate p-value using complementary error function
        p_value = math.erfc(s_obs / math.sqrt(2))
        
        return {
            "test_name": "Frequency (Monobit) Test",
            "p_value": p_value,
            "success": p_value >= 0.01,  # Standard NIST threshold
            "ones_count": np.sum(bits),
            "zeros_count": n - np.sum(bits),
            "sequence_length": n
        }
        
    def block_frequency_test(self, sequence=None, block_size=128) -> Dict:
        """
        Performs the NIST Block Frequency Test.
        
        This test evaluates the proportion of 1s within M-bit blocks, checking
        if it is approximately M/2, as would be expected for a random sequence.
        
        Args:
            sequence (bytes, optional): Sequence to test, uses self.sequence if None
            block_size (int): Size of blocks to analyze
            
        Returns:
            dict: Test results with p-value and success status
        """
        sequence = sequence if sequence is not None else self.sequence
        bits = self._bits_to_int_array(sequence)
        n = len(bits)
        
        # Ensure we have enough bits for at least one full block
        if n < block_size:
            return {
                "test_name": "Block Frequency Test",
                "error": f"Sequence too short for block size {block_size}",
                "success": False
            }
            
        # Calculate number of blocks (discard incomplete block at end if necessary)
        num_blocks = n // block_size
        
        # Calculate proportion of 1s in each block
        proportions = []
        for i in range(num_blocks):
            block = bits[i*block_size:(i+1)*block_size]
            proportion = np.sum(block) / block_size
            proportions.append(proportion)
            
        # Calculate chi-square statistic
        chi_squared = 4 * block_size * sum((p - 0.5)**2 for p in proportions)
        
        # Calculate p-value
        p_value = math.exp(-chi_squared / 2)
        if p_value > 1.0:  # Numerical precision issue
            p_value = 1.0
            
        return {
            "test_name": "Block Frequency Test",
            "block_size": block_size,
            "num_blocks": num_blocks,
            "p_value": p_value,
            "success": p_value >= 0.01,  # Standard NIST threshold
            "sequence_length": n
        }
        
    def runs_test(self, sequence=None) -> Dict:
        """
        Performs the NIST Runs Test.
        
        This test evaluates the total number of runs in the sequence, where a run
        is an uninterrupted sequence of identical bits. The test checks if the
        oscillation between 0s and 1s is too fast or too slow.
        
        Args:
            sequence (bytes, optional): Sequence to test, uses self.sequence if None
            
        Returns:
            dict: Test results with p-value and success status
        """
        sequence = sequence if sequence is not None else self.sequence
        bits = self._bits_to_int_array(sequence)
        n = len(bits)
        
        # Ensure minimum sequence length
        if n < 100:
            return {
                "test_name": "Runs Test",
                "error": "Sequence too short (minimum 100 bits required)",
                "success": False
            }
            
        # Calculate proportion of 1s
        pi = np.sum(bits) / n
        
        # Check if proportion of 1s is acceptable
        tau = 2 / math.sqrt(n)
        if abs(pi - 0.5) >= tau:
            return {
                "test_name": "Runs Test",
                "error": "Proportion of ones not within acceptable range",
                "pi": pi,
                "acceptable_range": f"0.5 ± {tau:.6f}",
                "success": False
            }
            
        # Count runs
        runs = 1  # Start with 1 for the first run
        for i in range(1, n):
            if bits[i] != bits[i-1]:
                runs += 1
                
        # Calculate test statistic
        v_obs = runs
        expected_runs = 2 * n * pi * (1 - pi)
        std_dev = math.sqrt(2 * n * pi * (1 - pi) * (1 - 2 * pi * (1 - pi)))
        
        # Calculate p-value
        z = (v_obs - expected_runs) / std_dev
        p_value = math.erfc(abs(z) / math.sqrt(2))
        
        return {
            "test_name": "Runs Test",
            "p_value": p_value,
            "success": p_value >= 0.01,  # Standard NIST threshold
            "runs_count": runs,
            "expected_runs": expected_runs,
            "sequence_length": n,
            "proportion_ones": pi
        }
        
    def longest_run_ones_test(self, sequence=None) -> Dict:
        """
        Performs the NIST Longest Run of Ones in a Block Test.
        
        This test evaluates the longest run of 1s within M-bit blocks, checking
        if it is consistent with what would be expected in a random sequence.
        
        Args:
            sequence (bytes, optional): Sequence to test, uses self.sequence if None
            
        Returns:
            dict: Test results with p-value and success status
        """
        sequence = sequence if sequence is not None else self.sequence
        bits = self._bits_to_int_array(sequence)
        n = len(bits)
        
        # Determine block size and reference distribution based on sequence length
        if n < 128:
            return {
                "test_name": "Longest Run of Ones Test",
                "error": "Sequence too short (minimum 128 bits required)",
                "success": False
            }
        elif n < 6272:
            M = 8
            K = 3
            # Probability table for block size M=8
            pi = [0.2148, 0.3672, 0.2305, 0.1875]
            v = [0, 1, 2, 3]  # Categories: longest run <= 1, = 2, = 3, >= 4
            block_count = n // M
        elif n < 750000:
            M = 128
            K = 5
            # Probability table for block size M=128
            pi = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]
            v = [0, 1, 2, 3, 4, 5]  # <= 4, = 5, = 6, = 7, = 8, >= 9
            block_count = n // M
        else:
            M = 10000
            K = 6
            # Probability table for block size M=10000
            pi = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]
            v = [0, 1, 2, 3, 4, 5, 6]  # <= 10, = 11, = 12, = 13, = 14, = 15, >= 16
            block_count = n // M
            
        # Process blocks and count longest runs
        frequencies = np.zeros(K + 1, dtype=int)
        
        for i in range(block_count):
            block = bits[i*M:(i+1)*M]
            
            # Find longest run in this block
            longest = 0
            current = 0
            
            for bit in block:
                if bit == 1:
                    current += 1
                    longest = max(longest, current)
                else:
                    current = 0
                    
            # Categorize
            if M == 8:
                if longest <= 1:
                    frequencies[0] += 1
                elif longest == 2:
                    frequencies[1] += 1
                elif longest == 3:
                    frequencies[2] += 1
                else:  # longest >= 4
                    frequencies[3] += 1
            elif M == 128:
                if longest <= 4:
                    frequencies[0] += 1
                elif longest == 5:
                    frequencies[1] += 1
                elif longest == 6:
                    frequencies[2] += 1
                elif longest == 7:
                    frequencies[3] += 1
                elif longest == 8:
                    frequencies[4] += 1
                else:  # longest >= 9
                    frequencies[5] += 1
            else:  # M == 10000
                if longest <= 10:
                    frequencies[0] += 1
                elif longest == 11:
                    frequencies[1] += 1
                elif longest == 12:
                    frequencies[2] += 1
                elif longest == 13:
                    frequencies[3] += 1
                elif longest == 14:
                    frequencies[4] += 1
                elif longest == 15:
                    frequencies[5] += 1
                else:  # longest >= 16
                    frequencies[6] += 1
                    
        # Calculate chi-square statistic
        chi_squared = sum((frequencies[i] - block_count * pi[i])**2 / (block_count * pi[i]) for i in range(len(pi)))
        
        # Calculate p-value
        p_value = math.exp(-chi_squared / 2)
        if p_value > 1.0:  # Numerical precision issue
            p_value = 1.0
            
        return {
            "test_name": "Longest Run of Ones Test",
            "block_size": M,
            "num_blocks": block_count,
            "frequencies": frequencies.tolist(),
            "expected_frequencies": [block_count * p for p in pi],
            "p_value": p_value,
            "success": p_value >= 0.01,  # Standard NIST threshold
            "sequence_length": n
        }
        
    def binary_matrix_rank_test(self, sequence=None, M=32, Q=32) -> Dict:
        """
        Performs the NIST Binary Matrix Rank Test.
        
        This test checks for linear dependence among fixed-length substrings of the
        original sequence by examining the ranks of disjoint sub-matrices.
        
        Args:
            sequence (bytes, optional): Sequence to test, uses self.sequence if None
            M (int): Number of rows in each matrix
            Q (int): Number of columns in each matrix
            
        Returns:
            dict: Test results with p-value and success status
        """
        sequence = sequence if sequence is not None else self.sequence
        bits = self._bits_to_int_array(sequence)
        n = len(bits)
        
        # Check if we have enough bits for at least one matrix
        if n < M * Q:
            return {
                "test_name": "Binary Matrix Rank Test",
                "error": f"Sequence too short for {M}x{Q} matrix",
                "success": False
            }
            
        # Determine number of matrices
        N = n // (M * Q)
        
        # Initialize rank counts
        full_rank = 0  # Rank = M
        full_rank_minus_1 = 0  # Rank = M-1
        remaining = 0  # Rank <= M-2
        
        # Process each matrix
        for k in range(N):
            # Extract bits for this matrix
            matrix_bits = bits[k * M * Q:(k + 1) * M * Q]
            
            # Reshape into MxQ matrix
            matrix = matrix_bits.reshape(M, Q)
            
            # Calculate rank using Gaussian elimination
            rank = self._calculate_matrix_rank(matrix)
            
            # Categorize by rank
            if rank == M:
                full_rank += 1
            elif rank == M - 1:
                full_rank_minus_1 += 1
            else:
                remaining += 1
                
        # Theoretical probabilities for a random sequence
        p_full = math.exp(q_function(M, Q) - q_function(M, M))
        p_full_minus_1 = math.exp(q_function(M - 1, Q) + q_function(M, M) - q_function(M, Q) - q_function(M - 1, M - 1))
        p_remaining = 1 - p_full - p_full_minus_1
        
        # Calculate chi-square statistic
        chi_squared = (
            ((full_rank - N * p_full)**2) / (N * p_full) +
            ((full_rank_minus_1 - N * p_full_minus_1)**2) / (N * p_full_minus_1) +
            ((remaining - N * p_remaining)**2) / (N * p_remaining)
        )
        
        # Calculate p-value
        p_value = math.exp(-chi_squared / 2)
        if p_value > 1.0:  # Numerical precision issue
            p_value = 1.0
            
        return {
            "test_name": "Binary Matrix Rank Test",
            "matrix_dim": f"{M}x{Q}",
            "num_matrices": N,
            "full_rank_count": full_rank,
            "full_rank_minus_1_count": full_rank_minus_1,
            "remaining_count": remaining,
            "expected_full_rank": N * p_full,
            "expected_full_rank_minus_1": N * p_full_minus_1,
            "expected_remaining": N * p_remaining,
            "p_value": p_value,
            "success": p_value >= 0.01,  # Standard NIST threshold
            "sequence_length": n
        }
        
    def _calculate_matrix_rank(self, matrix):
        """
        Calculate the rank of a binary matrix using Gaussian elimination.
        
        Args:
            matrix (numpy.ndarray): Binary matrix
            
        Returns:
            int: Rank of the matrix
        """
        # Make a copy of the matrix to avoid modifying the original
        M = matrix.copy()
        
        # Get dimensions
        num_rows, num_cols = M.shape
        
        # Initialize rank
        rank = 0
        
        # Gaussian elimination (adapted for binary field)
        for r in range(min(num_rows, num_cols)):
            # Find pivot
            pivot_found = False
            for i in range(r, num_rows):
                if M[i, r] == 1:
                    pivot_found = True
                    # Swap rows if necessary
                    if i != r:
                        M[[r, i]] = M[[i, r]]
                    break
                    
            if not pivot_found:
                continue
                
            # Eliminate below
            for i in range(r + 1, num_rows):
                if M[i, r] == 1:
                    M[i] = np.logical_xor(M[i], M[r]).astype(int)
                    
            rank += 1
            
        return rank
        
    def dft_test(self, sequence=None) -> Dict:
        """
        Performs the NIST Discrete Fourier Transform (Spectral) Test.
        
        This test detects periodic features in the sequence that would indicate
        deviation from randomness, focusing on the peak heights in the DFT.
        
        Args:
            sequence (bytes, optional): Sequence to test, uses self.sequence if None
            
        Returns:
            dict: Test results with p-value and success status
        """
        sequence = sequence if sequence is not None else self.sequence
        bits = self._bits_to_int_array(sequence)
        n = len(bits)
        
        # Convert 0s and 1s to -1s and 1s
        X = 2 * bits - 1
        
        # Compute DFT
        S = np.abs(np.fft.fft(X))
        
        # Take only first half (due to symmetry)
        S = S[:n//2]
        
        # Compute threshold
        T = np.sqrt(np.log(1.0/0.05) * n)
        
        # Count values that exceed threshold
        N0 = 0.95 * n / 2  # Expected count under randomness
        N1 = np.sum(S < T)  # Observed count
        
        # Calculate test statistic
        d = (N1 - N0) / np.sqrt(n * 0.95 * 0.05 / 4)
        
        # Calculate p-value
        p_value = math.erfc(abs(d) / math.sqrt(2))
        
        return {
            "test_name": "Discrete Fourier Transform Test",
            "threshold": T,
            "expected_below_threshold": N0,
            "observed_below_threshold": N1,
            "p_value": p_value,
            "success": p_value >= 0.01,  # Standard NIST threshold
            "sequence_length": n
        }
        
    def non_overlapping_template_test(self, sequence=None, template=None, block_size=8) -> Dict:
        """
        Performs the NIST Non-overlapping Template Matching Test.
        
        This test counts occurrences of pre-specified target strings and checks if
        the frequency is consistent with what would be expected for a random sequence.
        
        Args:
            sequence (bytes, optional): Sequence to test, uses self.sequence if None
            template (list): Template pattern to search for (default: [0,0,1])
            block_size (int): Size of blocks to analyze
            
        Returns:
            dict: Test results with p-value and success status
        """
        sequence = sequence if sequence is not None else self.sequence
        bits = self._bits_to_int_array(sequence)
        n = len(bits)
        
        # Set default template if none provided
        if template is None:
            template = [0, 0, 1]
        template = np.array(template)
        m = len(template)
        
        # Check if template size is valid
        if m >= block_size:
            return {
                "test_name": "Non-overlapping Template Test",
                "error": "Template size must be smaller than block size",
                "success": False
            }
            
        # Check if sequence is long enough
        if n < block_size:
            return {
                "test_name": "Non-overlapping Template Test",
                "error": f"Sequence too short for block size {block_size}",
                "success": False
            }
            
        # Calculate number of blocks
        N = n // block_size
        
        # Initialize counts for each block
        counts = np.zeros(N, dtype=int)
        
        # Process each block
        for i in range(N):
            block = bits[i*block_size:(i+1)*block_size]
            
            # Count non-overlapping occurrences in this block
            pos = 0
            while pos <= block_size - m:
                if np.array_equal(block[pos:pos+m], template):
                    counts[i] += 1
                    pos += m  # Skip ahead by template length (non-overlapping)
                else:
                    pos += 1
                    
        # Calculate theoretical mean and variance
        mu = (block_size - m + 1) / (2**m)
        sigma_squared = block_size * ((1/2**m) - ((2*m-1)/(2**(2*m))))
        
        # Calculate chi-square statistic
        chi_squared = np.sum(((counts - mu)**2) / sigma_squared)
        
        # Calculate p-value
        p_value = special.gammaincc(N/2, chi_squared/2)
        
        return {
            "test_name": "Non-overlapping Template Test",
            "template": template.tolist(),
            "block_size": block_size,
            "num_blocks": N,
            "expected_matches_per_block": mu,
            "p_value": p_value,
            "success": p_value >= 0.01,  # Standard NIST threshold
            "sequence_length": n
        }
        
    def overlapping_template_test(self, sequence=None, template=None, block_size=1032) -> Dict:
        """
        Performs the NIST Overlapping Template Matching Test.
        
        This test counts occurrences of pre-specified target strings, allowing
        overlapping, and checks if the frequency is consistent with randomness.
        
        Args:
            sequence (bytes, optional): Sequence to test, uses self.sequence if None
            template (list): Template pattern to search for (default: all 1s of length 9)
            block_size (int): Size of blocks to analyze
            
        Returns:
            dict: Test results with p-value and success status
        """
        sequence = sequence if sequence is not None else self.sequence
        bits = self._bits_to_int_array(sequence)
        n = len(bits)
        
        # Set default template if none provided (all 1s of length 9)
        if template is None:
            template = np.ones(9, dtype=int)
        else:
            template = np.array(template)
        m = len(template)
        
        # Check if template size is valid
        if m >= block_size:
            return {
                "test_name": "Overlapping Template Test",
                "error": "Template size must be smaller than block size",
                "success": False
            }
            
        # Check if sequence is long enough
        if n < block_size:
            return {
                "test_name": "Overlapping Template Test",
                "error": f"Sequence too short for block size {block_size}",
                "success": False
            }
            
        # Calculate number of blocks
        N = n // block_size
        
        # Define categories for frequencies
        K = 5
        v = [0, 1, 2, 3, 4, 5]  # Categories: 0, 1, 2, 3, 4, >=5 matches
        
        # Initialize frequency counts for each category
        frequencies = np.zeros(K + 1, dtype=int)
        
        # Process each block
        for i in range(N):
            block = bits[i*block_size:(i+1)*block_size]
            
            # Count overlapping occurrences in this block
            count = 0
            for j in range(block_size - m + 1):
                if np.array_equal(block[j:j+m], template):
                    count += 1
                    
            # Categorize result
            if count >= K:
                frequencies[K] += 1
            else:
                frequencies[count] += 1
                
        # Calculate probabilities using approximation
        eta = (block_size - m + 1) / (2**m)
        pi = [self._probability_for_overlapping_template(i, m, eta) for i in v]
        
        # Calculate chi-square statistic
        chi_squared = sum((frequencies[i] - N * pi[i])**2 / (N * pi[i]) for i in range(K + 1))
        
        # Calculate p-value
        p_value = special.gammaincc(K/2, chi_squared/2)
        
        return {
            "test_name": "Overlapping Template Test",
            "template": template.tolist(),
            "block_size": block_size,
            "num_blocks": N,
            "frequencies": frequencies.tolist(),
            "expected_frequencies": [N * p for p in pi],
            "p_value": p_value,
            "success": p_value >= 0.01,  # Standard NIST threshold
            "sequence_length": n
        }
        
    def _probability_for_overlapping_template(self, i, m, eta):
        """
        Calculate probability for overlapping template matching.
        
        This is an approximation using the binomial probability with mean lamda=eta
        and variance eta(1-2^(-m)).
        
        Args:
            i (int): Number of occurrences
            m (int): Template length
            eta (float): Mean
            
        Returns:
            float: Probability
        """
        lamda = eta
        variance = eta * (1 - 1/(2**m))
        
        if i == 0:
            return math.exp(-lamda)
        elif i == 5:  # Last category is cumulative (5 or more)
            return 1 - sum(self._probability_for_overlapping_template(j, m, eta) for j in range(5))
        else:
            return math.exp(-lamda) * (lamda**i) / math.factorial(i)
            
    def universal_test(self, sequence=None) -> Dict:
        """
        Performs Maurer's Universal Statistical Test.
        
        This test compresses the sequence and checks if the compression rate
        is consistent with what would be expected for a random sequence.
        
        Args:
            sequence (bytes, optional): Sequence to test, uses self.sequence if None
            
        Returns:
            dict: Test results with p-value and success status
        """
        sequence = sequence if sequence is not None else self.sequence
        bits = self._bits_to_int_array(sequence)
        n = len(bits)
        
        # Define parameters based on sequence length
        if n < 387840:
            return {
                "test_name": "Universal Test",
                "error": "Sequence too short (minimum 387,840 bits required)",
                "success": False
            }
            
        L = 6  # Block size
        Q = 10 * 2**L  # Initialization segment length
        K = n // L - Q  # Number of test blocks
        
        # Expected values for L=6 (from NIST paper)
        expected_value = 5.2177052
        variance = 2.954
        
        # Initialize state table
        state_table = {}
        
        # Initialize
        for i in range(Q):
            # Get L-bit block
            block = 0
            for j in range(L):
                if i*L + j < len(bits):
                    block = (block << 1) | bits[i*L + j]
            state_table[block] = i + 1
            
        # Test segment
        sum_value = 0.0
        for i in range(Q, Q + K):
            # Get L-bit block
            block = 0
            for j in range(L):
                if i*L + j < len(bits):
                    block = (block << 1) | bits[i*L + j]
                    
            # Calculate distance to previous occurrence
            distance = i + 1 - state_table.get(block, 0)
            sum_value += math.log2(distance) if distance > 0 else 0
            
            # Update state table
            state_table[block] = i + 1
            
        # Calculate test statistic
        fn = sum_value / K
        
        # Calculate normalized test statistic
        c = 0.7 - 0.8 / L + (4 + 32 / L) * (K**(-3/L)) / 15
        sigma = c * math.sqrt(variance / K)
        
        # Calculate p-value
        p_value = math.erfc(abs(fn - expected_value) / (math.sqrt(2) * sigma))
        
        return {
            "test_name": "Universal Test",
            "L": L,
            "Q": Q,
            "K": K,
            "fn": fn,
            "expected_value": expected_value,
            "p_value": p_value,
            "success": p_value >= 0.01,  # Standard NIST threshold
            "sequence_length": n
        }
        
    def serial_test(self, sequence=None, pattern_length=3) -> Dict:
        """
        Performs the NIST Serial Test.
        
        This test focuses on the frequency of all possible overlapping m-bit
        patterns across the entire sequence to determine if they appear with the
        same probability as would be expected for a random sequence.
        
        Args:
            sequence (bytes, optional): Sequence to test, uses self.sequence if None
            pattern_length (int): Length of bit patterns to consider
            
        Returns:
            dict: Test results with p-value and success status
        """
        sequence = sequence if sequence is not None else self.sequence
        bits = self._bits_to_int_array(sequence)
        n = len(bits)
        
        m = pattern_length
        
        # Check if pattern length is valid
        if m > int(math.log2(n)) - 2:
            return {
                "test_name": "Serial Test",
                "error": f"Pattern length too large for sequence length (max allowed: {int(math.log2(n)) - 2})",
                "success": False
            }
            
        # Extend the sequence by appending the first m-1 bits
        # This allows us to count patterns that wrap around
        padded_bits = np.concatenate([bits, bits[:m-1]])