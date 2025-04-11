# Chebyshev Cryptosystem for IoT and Digital Twins

A secure key exchange and encryption system based on Chebyshev polynomials, offering a chaos-based alternative to traditional cryptographic approaches, optimized for IoT, IIoT, and digital twin security applications.

## Overview

This cryptosystem implements a key exchange protocol using the semigroup property of Chebyshev polynomials over a prime field. It provides security parameters that scale appropriately with key size and includes comprehensive testing for the mathematical properties that ensure the security of the system. The lightweight implementation makes it particularly well-suited for resource-constrained IoT devices and real-time digital twin applications.

### Features

- **Chaos-Based Security**: Leverages the chaotic behavior of Chebyshev polynomials for cryptographic operations
- **IoT-Optimized**: Lightweight implementation suitable for resource-constrained devices
- **Digital Twin Ready**: Low latency design perfect for real-time synchronization of digital twins
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
   git clone https://github.com/yourusername/chebyshev-crypto.git
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

### For IoT and IIoT Applications

The system is designed with resource constraints in mind:

```python
from chebyshev.security import SecurityParams
from crypto.dh import ChebyshevDH

# Initialize with minimal security for IoT devices 
dh = ChebyshevDH(private_bits=16)  # Lower bit count for constrained devices

# Generate keys and exchange as normal
# ...
```

### For Digital Twin Applications

For real-time synchronization between physical assets and digital twins:

```python
from crypto.feistel import FeistelCipher
from crypto.sbox import SBoxGenerator

# Create lightweight cipher for real-time updates
sbox_gen = SBoxGenerator(shared_secret, box_size=16)  # Smaller S-box
sbox = sbox_gen.generate()

# Initialize faster Feistel cipher with fewer rounds
cipher = FeistelCipher(sbox, rounds=8, block_size=8)

# Use for secure data exchange between physical device and digital twin
encrypted_sensor_data = cipher.encrypt(sensor_reading)
```

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

# Generate keys for Alice (IoT device)
device_private, device_public, device_raw = dh.generate_keypair()

# Generate keys for Bob (cloud service)
service_private, service_public, service_raw = dh.generate_keypair()

# Device computes shared secret
device_shared = dh.compute_shared(device_private, service_raw)

# Service computes shared secret
service_shared = dh.compute_shared(service_private, device_raw)

# Verify that both parties have the same secret
assert device_shared == service_shared

# Create S-box from shared secret
sbox_gen = SBoxGenerator(device_shared)
sbox = sbox_gen.generate()

# Initialize Feistel cipher with the S-box
cipher = FeistelCipher(sbox, rounds=16)

# Encrypt a message
plaintext = b"IoT sensor reading: 23.5C"
ciphertext = cipher.encrypt(plaintext)

# Decrypt the message
decrypted = cipher.decrypt(ciphertext)
assert decrypted == plaintext
```

## Mathematical Background

### Chebyshev Polynomials and Chaos Theory

Chebyshev polynomials of the first kind, denoted as T_n(x), are defined by the recurrence relation:

- T₀(x) = 1
- T₁(x) = x
- Tₙ(x) = 2xTₙ₋₁(x) - Tₙ₋₂(x) for n ≥ 2

When computed over a prime field (modulo a large prime p), they exhibit chaotic behavior which is ideal for cryptographic applications, especially in IoT scenarios where unpredictability is crucial.

### Key Security Properties

1. **Semigroup Property**: T_r(T_s(x)) = T_{rs}(x) mod p
2. **Commutativity**: T_r(T_s(x)) = T_s(T_r(x)) mod p

These properties allow for secure key exchange similar to the Diffie-Hellman protocol, but based on chaotic systems that provide enhanced security for IoT applications.

### Feistel Network

The Feistel network is a symmetric structure used in block ciphers. It consists of multiple rounds where the block is divided into two parts, and one part is transformed using a round function that depends on the other part and a subkey. The Feistel structure is particularly suitable for IoT devices due to its simplicity and minimal resource requirements.

### S-boxes

Substitution boxes (S-boxes) are a basic component of symmetric key algorithms which perform substitution. In our implementation, S-boxes are dynamically generated from the shared secret, providing a unique transformation for each key exchange session, which is ideal for protecting sensitive IoT data.

## IoT and Digital Twin Applications

### IoT Security Challenges Addressed

- **Resource Constraints**: The lightweight implementation requires minimal computational resources
- **Energy Efficiency**: Optimized algorithms reduce power consumption for battery-powered devices
- **Low Latency**: Fast encryption and decryption suitable for real-time applications
- **Scalability**: Works across heterogeneous IoT networks with varying device capabilities
- **Edge Computing**: Can be deployed directly on edge devices without cloud dependency

### Digital Twin Security Benefits

- **Secure Synchronization**: Ensures data integrity between physical assets and digital models
- **Real-Time Updates**: Low overhead allows for secure real-time data transmission
- **Privacy Preservation**: Protects sensitive operational data in industrial settings
- **Authentication**: Provides mutual authentication between physical devices and their digital twins
- **Integrity Protection**: Prevents manipulation of data flowing between physical and digital realms

## IIoT-Specific Considerations

- **OT/IT Convergence**: Bridges the security gap between operational and information technology
- **Protocol Integration**: Compatible with common IIoT protocols through simple adaptation layers
- **Legacy System Support**: Can secure communications involving legacy industrial systems
- **Regulatory Compliance**: Helps meet IEC 62443 and other industrial security standards
- **Supply Chain Security**: Secures data throughout industrial supply chains and ecosystems

## Security Considerations

- The security of this system leverages the chaotic behavior of Chebyshev polynomials
- Key sizes are automatically scaled to maintain appropriate security levels while considering IoT constraints
- The system enforces minimum key sizes to prevent insecure configurations
- The Feistel cipher implementation uses dynamically generated S-boxes from the shared secret, enhancing security
- The number of Feistel rounds can be adjusted to balance security and performance based on device capabilities
- CBC mode with a random IV is used for the Feistel cipher to prevent pattern analysis
- Security testing includes avalanche effect, statistical randomness, and invertibility tests

## Performance

The implementation uses several optimizations for Chebyshev polynomial evaluation:

- **Matrix exponentiation** for large polynomial degrees
- **NumPy coefficient calculation** for medium-sized degrees
- **Memoized recursive calculation** for smaller degrees
- **Binary exponentiation** for efficient computation

These optimizations make the system particularly well-suited for IoT and digital twin applications where computational resources may be limited.

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
│   ├── interface.py            # Main UI coordinator
│   ├── input_handler.py        # Input handling and validation
│   ├── display_handler.py      # Information display
│   └── analysis_display.py     # Analysis and test results display
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
- Create specialized lightweight profiles for different IoT device classes
- Add MQTT and CoAP integration examples for IoT protocols
- Develop OPC UA security layer for industrial applications
- Create a web-based dashboard for digital twin security monitoring
- Add Docker containerization for edge deployment
- Implement a RESTful API for cloud-based key management

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Based on research into chaos-based cryptography for cyber-physical systems
- Inspired by the need for lightweight, efficient security solutions for IoT and IIoT environments
- Designed with input from digital twin implementation specialists
- Feistel network design optimized for resource-constrained environments
