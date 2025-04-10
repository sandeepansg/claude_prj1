"""
Mathematical property verification for Chebyshev-based cryptosystems.
"""
import random


class PropertyVerifier:
    """Verifies mathematical properties essential for Chebyshev polynomial security."""

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
