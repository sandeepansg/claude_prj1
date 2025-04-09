# Chebyshev Cryptosystem

A secure key exchange system based on Chebyshev polynomials, offering a quantum-resistant alternative to traditional Diffie-Hellman, with additional Feistel cipher functionality using dynamically generated S-boxes.

## Overview

This cryptosystem implements a key exchange protocol using the semigroup property of Chebyshev polynomials over a prime field. It provides security parameters that scale appropriately with key size and includes comprehensive testing for the mathematical properties that ensure the security of the system. The system also includes a Feistel cipher implementation that uses S-boxes dynamically generated from the shared secret.

### Features

- **Quantum-Resistant Key Exchange**: Based on the hardness of Chebyshev polynomial discrete logarithm problem
- **Scalable Security**: Automatically adjusts security parameters based on desired private key strength
- **Optimized Polynomial Calculation**: Uses multiple evaluation strategies based on polynomial degree
- **Mathematical Verification**: Tests semigroup and commutativity properties critical to security
- **User-Friendly Interface**: Simple command-line interface for demonstrations and testing
- **Modular Architecture**: Clean separation of concerns for maintainability and reusability
- **Feistel Cipher**: Implementation of the Feistel structure for symmetric encryption
- **Dynamic S-boxes**: S-boxes generated from the shared secret for enhanced security
- **Complete Encryption Pipeline**: Key exchange followed by symmetric encryption
- **Cryptographic Analysis**: Tests avalanche effect, statistical properties, and S-box quality

## Installation

### Prerequisites

- Python 3.7+
- NumPy
- SymPy

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/sandeepansg/chebyshev-crypto.git
   cd chebyshev-crypto
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Basic Demo

Run the demonstration script to generate keys, perform a key exchange, verify security properties, and demonstrate the Feistel cipher:

```
python main.py
```

The interactive demo will guide you through:
- Setting security parameters
- Generating key pairs
- Performing a key exchange
- Verifying mathematical properties
- Generating an S-box from the shared secret
- Encrypting and decrypting a message using a Feistel cipher
- Analyzing the security of the implementation

### As a Library

You can import the components and use them in your own applications:

```python
from chebyshev.poly import ChebyshevPoly
from chebyshev.security import SecurityParams
from crypto.dh import ChebyshevDH
from crypto.feistel import FeistelCipher
from crypto.sbox import SBoxGenerator

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

# Create S-box from shared secret
sbox_gen = SBoxGenerator(alice_shared)
sbox = sbox_gen.generate()

# Initialize Feistel cipher with the S-box
cipher = FeistelCipher(sbox, rounds=16)

# Encrypt a message
plaintext = b"This is a secret message"
ciphertext = cipher.encrypt(plaintext)

# Decrypt the message
decrypted = cipher.decrypt(ciphertext)
assert decrypted == plaintext
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

### Feistel Network

The Feistel network is a symmetric structure used in block ciphers. It consists of multiple rounds where the block is divided into two parts, and one part is transformed using a round function that depends on the other part and a subkey. The Feistel structure has the advantage that encryption and decryption operations are very similar, even identical in some cases, requiring only a reversal of the key schedule.

### S-boxes

Substitution boxes (S-boxes) are a basic component of symmetric key algorithms which perform substitution. In our implementation, S-boxes are dynamically generated from the shared secret, providing a unique transformation for each key exchange session.

## Security Considerations

- The security of this system relies on the difficulty of the Chebyshev polynomial discrete logarithm problem
- Key sizes are automatically scaled to maintain appropriate security levels
- For production use, consider using longer key lengths (64-bit private keys or larger)
- The system enforces minimum key sizes to prevent insecure configurations
- The Feistel cipher implementation uses dynamically generated S-boxes from the shared secret, enhancing security
- The number of Feistel rounds can be adjusted to balance security and performance
- CBC mode with a random IV is used for the Feistel cipher to prevent pattern analysis
- Security testing includes avalanche effect, statistical randomness, and invertibility tests

## Performance

The implementation uses several optimizations for Chebyshev polynomial evaluation:

- **Matrix exponentiation** for large polynomial degrees
- **NumPy coefficient calculation** for medium-sized degrees
- **Memoized recursive calculation** for smaller degrees
- **Binary exponentiation** for efficient computation

The Feistel cipher implementation is also optimized for performance while maintaining a high level of security.

## Project Structure

```
chebyshev-crypto/
├── __init__.py                 # Package exports
├── chebyshev/
│   ├── __init__.py             # Chebyshev module exports
│   ├── poly.py                 # Polynomial implementation
│   └── security.py             # Security parameter handling
├── crypto/
│   ├── __init__.py             # Crypto module exports
│   ├── dh.py                   # Diffie-Hellman implementation
│   ├── feistel.py              # Feistel cipher implementation
│   ├── sbox.py                 # S-box generation from shared secret
│   └── tester.py               # Security property testing
├── ui/
│   ├── __init__.py             # UI module exports
│   └── interface.py            # User interface functions
├── main.py                     # Demo entry point
└── requirements.txt            # Dependencies
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Future Enhancements

- Add support for key derivation function (KDF) to convert shared secrets into cryptographic keys
- Implement additional block cipher modes (CTR, GCM)
- Add digital signature scheme based on Chebyshev polynomials
- Create a web-based demo interface
- Add benchmarking tools for performance comparison with traditional algorithms
- Implement hardware acceleration for polynomial evaluation

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Based on research into Chebyshev polynomials as a post-quantum cryptographic primitive
- Inspired by the need for alternatives to discrete logarithm-based cryptosystems that are vulnerable to quantum algorithms
- Feistel network design inspired by classic symmetric ciphers like DES and Blowfish
