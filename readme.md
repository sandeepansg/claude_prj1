# Chebyshev Cryptosystem

A secure key exchange system based on Chebyshev polynomials, offering a quantum-resistant alternative to traditional Diffie-Hellman.

## Overview

This cryptosystem implements a key exchange protocol using the semigroup property of Chebyshev polynomials over a prime field. It provides security parameters that scale appropriately with key size and includes comprehensive testing for the mathematical properties that ensure the security of the system.

### Features

- **Scalable Security**: Automatically adjusts security parameters based on desired private key strength
- **Optimized Polynomial Calculation**: Uses multiple evaluation strategies based on polynomial degree
- **Mathematical Verification**: Tests semigroup and commutativity properties critical to security
- **User-Friendly Interface**: Simple command-line interface for demonstrations and testing
- **Modular Architecture**: Clean separation of concerns for maintainability and reusability

## Installation

### Prerequisites

- Python 3.7+
- NumPy
- SymPy

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/sandeepansg/claude_prj1.git
   cd claude_prj1
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Basic Demo

Run the demonstration script to generate keys, perform a key exchange, and verify security properties:

```
python main.py
```

### As a Library

You can import the components and use them in your own applications:

```python
from chebyshev_cryptosystem import ChebyshevDH

# Initialize with 32-bit private keys
dh = ChebyshevDH(private_bits=32)

# Generate keys for Alice
alice_private, alice_public, alice_raw = dh.generate_keypair()

# Generate keys for Bob
bob_private, bob_public, bob_raw = dh.generate_keypair()

# Alice computes shared secret
alice_shared = dh.compute_shared(alice_private, bob_raw)

# Bob computes shared secret
bob_shared = dh.compute_shared(bob_private, alice_raw)

# Verify that both parties have the same secret
assert alice_shared == bob_shared
```

## Mathematical Background

### Chebyshev Polynomials

Chebyshev polynomials of the first kind, denoted as T_n(x), are defined by the recurrence relation:

- T₀(x) = 1
- T₁(x) = x
- Tₙ(x) = 2xTₙ₋₁(x) - Tₙ₋₂(x) for n ≥ 2

When computed over a prime field (modulo a large prime p), they exhibit useful properties for cryptography.

### Key Security Properties

1. **Semigroup Property**: T_r(T_s(x)) = T_{rs}(x) mod p
2. **Commutativity**: T_r(T_s(x)) = T_s(T_r(x)) mod p

These properties allow for secure key exchange similar to the Diffie-Hellman protocol, but based on the difficulty of the Chebyshev polynomial discrete logarithm problem, which is believed to be resistant to quantum attacks.

## Project Structure

```
claude_prj1/
├── __init__.py                 # Package exports
├── chebyshev/
│   ├── __init__.py             # Chebyshev module exports
│   ├── poly.py                 # Polynomial implementation
│   └── security.py             # Security parameter handling
├── crypto/
│   ├── __init__.py             # Crypto module exports
│   ├── dh.py                   # Diffie-Hellman implementation
│   └── tester.py               # Security property testing
├── ui/
│   ├── __init__.py             # UI module exports
│   └── interface.py            # User interface functions
├── main.py                     # Demo entry point
└── requirements.txt            # Dependencies
```

## Security Considerations

- The security of this system relies on the difficulty of the Chebyshev polynomial discrete logarithm problem
- Key sizes are automatically scaled to maintain appropriate security levels
- For production use, consider using longer key lengths (64-bit private keys or larger)
- The system enforces minimum key sizes to prevent insecure configurations

## Performance

The implementation uses several optimizations for Chebyshev polynomial evaluation:

- **Matrix exponentiation** for large polynomial degrees
- **NumPy coefficient calculation** for medium-sized degrees
- **Memoized recursive calculation** for smaller degrees
- **Binary exponentiation** for efficient computation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Based on research into Chebyshev polynomials as a post-quantum cryptographic primitive
- Inspired by the need for alternatives to discrete logarithm-based cryptosystems that are vulnerable to quantum algorithms
