# fips-crypto

[![CI](https://github.com/fzheng/fips-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/fzheng/fips-crypto/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/fips-crypto.svg)](https://www.npmjs.com/package/fips-crypto)
[![license](https://img.shields.io/npm/l/fips-crypto.svg?color=blue)](https://github.com/fzheng/fips-crypto/blob/main/LICENSE)
[![codecov](https://codecov.io/gh/fzheng/fips-crypto/graph/badge.svg?token=X6HH8RWTDZ)](https://codecov.io/gh/fzheng/fips-crypto)
[![FIPS 203](https://img.shields.io/badge/FIPS%20203-ML--KEM-blue)](https://csrc.nist.gov/pubs/fips/203/final)

A post-quantum cryptography library for JavaScript/TypeScript implementing NIST FIPS standards.

Built with Rust and WebAssembly for high performance in both Node.js and browser environments.

## Features

- **ML-KEM (FIPS 203)** - Module-Lattice-Based Key-Encapsulation Mechanism
  - ML-KEM-512 (Security Category 1, ~AES-128)
  - ML-KEM-768 (Security Category 3, ~AES-192) - **Recommended**
  - ML-KEM-1024 (Security Category 5, ~AES-256)

- **ML-DSA (FIPS 204)** - Module-Lattice-Based Digital Signature Algorithm *(Coming Soon)*
  - ML-DSA-44 (Security Category 2)
  - ML-DSA-65 (Security Category 3) - **Recommended**
  - ML-DSA-87 (Security Category 5)

- **SLH-DSA (FIPS 205)** - Stateless Hash-Based Digital Signature Algorithm *(Coming Soon)*
  - 12 parameter sets (SHA2/SHAKE × 128/192/256 × fast/small)

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [API Reference](#api-reference)
- [Building from Source](#building-from-source)
- [Development](#development)
- [Algorithm Parameters](#algorithm-parameters)
- [Security Considerations](#security-considerations)
- [Standards Compliance](#standards-compliance)

---

## Installation

### From npm

```bash
npm install fips-crypto
```

### From Source

See [Building from Source](#building-from-source) below.

---

## Quick Start

```typescript
import { init, ml_kem768 } from 'fips-crypto';

// Initialize the WASM module (required once before using any functions)
await init();

// Generate a key pair
const { publicKey, secretKey } = await ml_kem768.keygen();

// Alice encapsulates a shared secret for Bob using his public key
const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);

// Bob decapsulates to get the same shared secret
const bobSecret = await ml_kem768.decapsulate(secretKey, ciphertext);

// Both parties now have the same 32-byte shared secret
// Use it for symmetric encryption (e.g., AES-256-GCM)
console.log('Secrets match:', Buffer.from(sharedSecret).equals(Buffer.from(bobSecret)));
```

---

## Usage Examples

### Node.js (ES Modules)

```typescript
import { init, ml_kem768, ml_kem512, ml_kem1024 } from 'fips-crypto';

async function main() {
  // Initialize WASM module
  await init();

  // ML-KEM-768 is recommended for most use cases
  const { publicKey, secretKey } = await ml_kem768.keygen();

  console.log('Public Key:', publicKey.length, 'bytes');
  console.log('Secret Key:', secretKey.length, 'bytes');

  // Encapsulate
  const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);
  console.log('Ciphertext:', ciphertext.length, 'bytes');
  console.log('Shared Secret:', Buffer.from(sharedSecret).toString('hex'));

  // Decapsulate
  const recovered = await ml_kem768.decapsulate(secretKey, ciphertext);
  console.log('Recovered Secret:', Buffer.from(recovered).toString('hex'));
}

main().catch(console.error);
```

### Node.js (CommonJS)

```javascript
const { init, ml_kem768 } = require('fips-crypto');

async function main() {
  await init();

  const { publicKey, secretKey } = await ml_kem768.keygen();
  const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);
  const recovered = await ml_kem768.decapsulate(secretKey, ciphertext);

  console.log('Success:', Buffer.compare(sharedSecret, recovered) === 0);
}

main();
```

### Browser (with bundler like Vite, Webpack, etc.)

```typescript
import { init, ml_kem768 } from 'fips-crypto';

async function setupQuantumSafeChannel() {
  // Initialize WASM (loads the .wasm file)
  await init();

  // Generate key pair
  const { publicKey, secretKey } = await ml_kem768.keygen();

  // Send publicKey to the other party...

  return { publicKey, secretKey };
}

async function encapsulateSecret(recipientPublicKey: Uint8Array) {
  const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(recipientPublicKey);

  // Send ciphertext to recipient
  // Use sharedSecret for AES-GCM encryption

  return { ciphertext, sharedSecret };
}
```

### Deterministic Key Generation (for testing)

```typescript
import { init, ml_kem768 } from 'fips-crypto';

await init();

// Use a 64-byte seed for deterministic key generation
const seed = new Uint8Array(64);
seed.fill(0x42);

const keypair1 = await ml_kem768.keygen(seed);
const keypair2 = await ml_kem768.keygen(seed);

// Both keypairs are identical
console.log('Same keys:',
  Buffer.from(keypair1.publicKey).equals(Buffer.from(keypair2.publicKey))
);
```

### Error Handling

```typescript
import { init, ml_kem768, FipsCryptoError, ErrorCodes } from 'fips-crypto';

await init();

try {
  // This will fail - wrong key length
  const invalidKey = new Uint8Array(100);
  await ml_kem768.encapsulate(invalidKey);
} catch (error) {
  if (error instanceof FipsCryptoError) {
    console.log('Error code:', error.code); // 'INVALID_KEY_LENGTH'
    console.log('Message:', error.message);
  }
}

try {
  // This will fail - seed must be exactly 64 bytes for keygen
  const badSeed = new Uint8Array(32);
  await ml_kem768.keygen(badSeed);
} catch (error) {
  if (error instanceof FipsCryptoError) {
    console.log('Error code:', error.code); // 'INVALID_SEED_LENGTH'
  }
}
```

---

## API Reference

### Initialization

#### `init(): Promise<void>`

Initialize the WASM module. Must be called before using any cryptographic functions.

- Safe to call multiple times (subsequent calls are no-ops)
- Safe to call concurrently (parallel calls share the same initialization promise)
- Throws `FipsCryptoError` with code `WASM_NOT_INITIALIZED` if the WASM module fails to load

```typescript
import { init } from 'fips-crypto';
await init();
```

### ML-KEM (Key Encapsulation)

#### `ml_kem512 | ml_kem768 | ml_kem1024`

Each ML-KEM variant provides the following methods:

##### `keygen(seed?: Uint8Array): Promise<MlKemKeyPair>`

Generate a key pair.

- `seed` (optional): 64-byte seed for deterministic generation
- Returns: `{ publicKey: Uint8Array, secretKey: Uint8Array }`
- Throws: `INVALID_SEED_LENGTH` if seed is provided but not exactly 64 bytes

##### `encapsulate(publicKey: Uint8Array, seed?: Uint8Array): Promise<MlKemEncapsulation>`

Encapsulate a shared secret.

- `publicKey`: Recipient's public key
- `seed` (optional): 32-byte seed for deterministic encapsulation
- Returns: `{ ciphertext: Uint8Array, sharedSecret: Uint8Array }`
- Throws: `INVALID_KEY_LENGTH` if public key has wrong length
- Throws: `INVALID_SEED_LENGTH` if seed is provided but not exactly 32 bytes

##### `decapsulate(secretKey: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>`

Decapsulate to recover the shared secret.

- `secretKey`: Your secret key
- `ciphertext`: The ciphertext from encapsulation
- Returns: 32-byte shared secret
- Throws: `INVALID_KEY_LENGTH` if secret key has wrong length
- Throws: `INVALID_CIPHERTEXT_LENGTH` if ciphertext has wrong length

##### `params: MlKemParams`

Parameter set information:

```typescript
{
  name: 'ML-KEM-768',
  securityCategory: 3,
  publicKeyBytes: 1184,
  secretKeyBytes: 2400,
  ciphertextBytes: 1088,
  sharedSecretBytes: 32
}
```

---

## Building from Source

### Prerequisites

#### 1. Install Rust

**macOS / Linux:**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Follow the prompts, then restart your terminal or run:
source $HOME/.cargo/env
```

**Windows:**

Download and run [rustup-init.exe](https://rustup.rs/). During installation, you will be prompted to install the Visual Studio C++ Build Tools — follow the instructions to install them. After installation, restart your terminal.

```bash
# Verify installation
rustc --version
cargo --version
```

#### 2. Add WebAssembly Target

```bash
rustup target add wasm32-unknown-unknown
```

#### 3. Install wasm-pack

```bash
# Using cargo
cargo install wasm-pack

# Or using npm
npm install -g wasm-pack

# Verify installation
wasm-pack --version
```

#### 4. Install Node.js (18+)

Download from [nodejs.org](https://nodejs.org/) or use a version manager like `nvm` (macOS/Linux) or [nvm-windows](https://github.com/coreybutler/nvm-windows) (Windows).

### Build Steps

```bash
# Clone the repository
git clone https://github.com/fzheng/fips-crypto.git
cd fips-crypto

# Install Node.js dependencies
npm install

# Build everything (WASM + TypeScript)
npm run build

# Run tests
npm test
```

### Build Scripts

| Command | Description |
|---------|-------------|
| `npm run build:wasm` | Build WASM module |
| `npm run build:ts` | Compile TypeScript |
| `npm run build` | Build everything |
| `npm test` | Run test suite |
| `npm run test:coverage` | Run tests with coverage |
| `npm run bench` | Run benchmarks |
| `npm run lint` | Run ESLint |
| `npm run clean` | Clean build artifacts |

---

## Development

### Running Tests

```bash
# Run all JavaScript/TypeScript tests (unit + compliance + property-based)
npm test

# Run Rust tests
cargo test

# Run tests with coverage
npm run test:coverage
```

### Test Suite

The test suite covers both Rust (`cargo test`) and JavaScript/TypeScript (`npm test`) layers:

- **Unit tests**: Comprehensive parameter validation, input validation, and functional tests for all ML-KEM variants
- **Compliance tests**: FIPS 203 KAT (Known Answer Test) vector verification against an independent implementation
- **Property-based tests**: Randomized testing with [fast-check](https://github.com/dubzzz/fast-check) to verify cryptographic properties (roundtrip correctness, determinism, seed validation) hold for arbitrary inputs
- **Error path tests**: WASM initialization failure, invalid inputs, and uninitialized module handling

Coverage thresholds: 99% statements, 99% functions, 98% branches, 99% lines.

### Adding New Features

1. Implement in Rust under `rust/src/`
2. Add WASM bindings in `rust/src/lib.rs` or module file
3. Create TypeScript wrapper in `src/`
4. Add unit tests in `tests/unit/`
5. Run full test suite

---

## Algorithm Parameters

### ML-KEM (FIPS 203)

| Parameter Set | Security | Public Key | Secret Key | Ciphertext | Shared Secret |
|---------------|----------|------------|------------|------------|---------------|
| ML-KEM-512    | Cat. 1   | 800 B      | 1,632 B    | 768 B      | 32 B          |
| ML-KEM-768    | Cat. 3   | 1,184 B    | 2,400 B    | 1,088 B    | 32 B          |
| ML-KEM-1024   | Cat. 5   | 1,568 B    | 3,168 B    | 1,568 B    | 32 B          |

### ML-DSA (FIPS 204)

| Parameter Set | Security | Public Key | Secret Key | Signature |
|---------------|----------|------------|------------|-----------|
| ML-DSA-44     | Cat. 2   | 1,312 B    | 2,560 B    | 2,420 B   |
| ML-DSA-65     | Cat. 3   | 1,952 B    | 4,032 B    | 3,293 B   |
| ML-DSA-87     | Cat. 5   | 2,592 B    | 4,896 B    | 4,627 B   |

### SLH-DSA (FIPS 205)

| Parameter Set       | Security | Public Key | Secret Key | Signature |
|---------------------|----------|------------|------------|-----------|
| SLH-DSA-SHA2-128f   | 128-bit  | 32 B       | 64 B       | 17,088 B  |
| SLH-DSA-SHA2-128s   | 128-bit  | 32 B       | 64 B       | 7,856 B   |
| SLH-DSA-SHA2-192f   | 192-bit  | 48 B       | 96 B       | 35,664 B  |
| SLH-DSA-SHA2-192s   | 192-bit  | 48 B       | 96 B       | 16,224 B  |
| SLH-DSA-SHA2-256f   | 256-bit  | 64 B       | 128 B      | 49,856 B  |
| SLH-DSA-SHA2-256s   | 256-bit  | 64 B       | 128 B      | 29,792 B  |

*Note: "f" variants are faster, "s" variants produce smaller signatures.*

---

## Security Considerations

### Implementation Security

- **Implicit Rejection**: ML-KEM implements implicit rejection to prevent chosen-ciphertext attacks
- **Input Validation**: All key, ciphertext, and seed lengths are validated before processing
- **Memory Zeroization**: All secret key material is securely erased when no longer needed
- **Constant-Time Operations**: Critical operations avoid data-dependent timing

### Quantum Resistance

These algorithms are designed to resist attacks from quantum computers:

| Algorithm | Mathematical Basis | Quantum Resistance |
|-----------|-------------------|-------------------|
| ML-KEM    | Module-LWE problem | Lattice-based |
| ML-DSA    | Module-LWE problem | Lattice-based |
| SLH-DSA   | Hash functions | Hash-based (conservative) |

### Recommendations

- Use **ML-KEM-768** for general key encapsulation
- Use **ML-DSA-65** for general digital signatures
- Use **SLH-DSA** when you want hash-based security (no lattice assumptions)
- Consider **hybrid schemes** combining classical and post-quantum algorithms during transition

---

## Standards Compliance

This library implements algorithms standardized by NIST:

- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM (August 2024)
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA (August 2024)
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) - SLH-DSA (August 2024)

### Compliance Verification

ML-KEM compliance is verified through Known Answer Tests (KAT): pre-generated key pairs, ciphertexts, and shared secrets produced by an independent FIPS 203 implementation are included as static test vectors. Our library must successfully decapsulate each ciphertext and recover the identical shared secret. This covers all three parameter sets (ML-KEM-512, ML-KEM-768, ML-KEM-1024).

The Rust implementation includes detailed references to specific FIPS 203 algorithm numbers (Algorithms 7-18) in source code comments.

### Migration Timeline

Per NIST IR 8547, organizations should:
- Begin transitioning to post-quantum cryptography **now**
- Deprecate quantum-vulnerable algorithms by **2030** (high-value data)
- Remove quantum-vulnerable algorithms by **2035**

---

## Major Contributors

- **Feng Zheng** - [GitHub](https://github.com/fzheng)

## License

MIT License

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Ensure linting passes (`npm run lint`)
4. Ensure all tests pass (`npm test`)
5. Submit a pull request

For major changes, please open an issue first to discuss the proposed changes.
