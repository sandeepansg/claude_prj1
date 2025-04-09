"""
Security property testing for Chebyshev-based cryptosystems.
"""
import random


class SecurityTester:
    """Tests mathematical properties essential for security."""

    def __init__(self, dh_instance):
        self.dh = dh_instance
        self.cheby = dh_instance.cheby
        self.mod = dh_instance.mod

    def test_semigroup(self, count, r, s):
        """Test semigroup property: T_r(T_s(x)) = T_{r*s}(x) mod q"""
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
