# fips-crypto

[![CI](https://github.com/fzheng/fips-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/fzheng/fips-crypto/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/fips-crypto.svg)](https://www.npmjs.com/package/fips-crypto)
[![license](https://img.shields.io/npm/l/fips-crypto.svg?color=blue)](https://github.com/fzheng/fips-crypto/blob/main/LICENSE)
[![codecov](https://codecov.io/gh/fzheng/fips-crypto/graph/badge.svg?token=X6HH8RWTDZ)](https://codecov.io/gh/fzheng/fips-crypto)
[![FIPS 203](https://img.shields.io/badge/FIPS%20203-ML--KEM-blue)](https://csrc.nist.gov/pubs/fips/203/final)
[![FIPS 204](https://img.shields.io/badge/FIPS%20204-ML--DSA-blue)](https://csrc.nist.gov/pubs/fips/204/final)

Post-quantum cryptography for Node.js and browsers, implementing FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA). Built in Rust, compiled to WebAssembly for high performance with constant-time operations, memory zeroization, and supply chain integrity verification.

### Why fips-crypto?

| Feature | fips-crypto | Pure-JS alternatives |
|---------|------------|---------------------|
| Implementation | Rust compiled to WASM | JavaScript |
| Constant-time operations | Yes (Rust, no secret-dependent branching) | Typically no |
| Memory zeroization | Yes (`zeroize` crate, automatic on drop) | Not reliable (GC) |
| Supply chain verification | SHA-256 checksums + npm provenance | Varies |
| FIPS 203 (ML-KEM) | All 3 parameter sets | Varies |
| FIPS 204 (ML-DSA) | All 3 parameter sets | Varies |

## Features

- **ML-KEM (FIPS 203)** - Module-Lattice-Based Key-Encapsulation Mechanism
  - ML-KEM-512 (Security Category 1, ~AES-128)
  - ML-KEM-768 (Security Category 3, ~AES-192) - **Recommended**
  - ML-KEM-1024 (Security Category 5, ~AES-256)

- **ML-DSA (FIPS 204)** - Module-Lattice-Based Digital Signature Algorithm
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

### Subpackage Imports

Import only what you need to minimize bundle size:

```typescript
import { ml_kem768 } from 'fips-crypto/ml-kem';
import { ml_dsa65 } from 'fips-crypto/ml-dsa';
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

// --- ML-DSA: Digital Signatures ---
import { ml_dsa65 } from 'fips-crypto';

// Generate signing key pair
const { publicKey: pk, secretKey: sk } = await ml_dsa65.keygen();

// Sign a message
const message = new TextEncoder().encode('Hello, post-quantum world!');
const signature = await ml_dsa65.sign(sk, message);

// Verify the signature
const valid = await ml_dsa65.verify(pk, message, signature);
console.log('Signature valid:', valid); // true
```

---

## Performance

Benchmarked with `npm run bench` (vitest bench, Node.js 22, Windows 11, AMD Ryzen 7 5800X).

### ML-KEM (FIPS 203)

| Operation | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|-----------|-----------|-----------|------------|
| keygen | 25,382 ops/s (39 us) | 18,008 ops/s (56 us) | 9,261 ops/s (108 us) |
| encapsulate | 26,544 ops/s (38 us) | 17,125 ops/s (58 us) | 12,650 ops/s (79 us) |
| decapsulate | 24,457 ops/s (41 us) | 14,096 ops/s (71 us) | 10,246 ops/s (98 us) |

### ML-DSA (FIPS 204)

| Operation | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|-----------|----------|----------|----------|
| keygen | 10,868 ops/s (92 us) | 7,095 ops/s (141 us) | 3,944 ops/s (254 us) |
| sign | 3,730 ops/s (268 us) | 1,734 ops/s (577 us) | 1,510 ops/s (662 us) |
| verify | 13,906 ops/s (72 us) | 6,973 ops/s (143 us) | 3,868 ops/s (259 us) |

All operations run in Rust/WASM with constant-time critical paths. Reproduce with `npm run bench`.

---

## Usage Examples

### Key Encapsulation (ML-KEM)

```typescript
import { init, ml_kem768 } from 'fips-crypto';

await init();

// Alice generates a key pair
const { publicKey, secretKey } = await ml_kem768.keygen();

// Bob encapsulates a shared secret using Alice's public key
const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);

// Alice decapsulates to get the same shared secret
const recovered = await ml_kem768.decapsulate(secretKey, ciphertext);

// Both parties now share a 32-byte secret for symmetric encryption
console.log('Match:', Buffer.from(sharedSecret).equals(Buffer.from(recovered)));
```

### Digital Signatures (ML-DSA)

```typescript
import { init, ml_dsa65 } from 'fips-crypto';

await init();

// Generate a signing key pair
const { publicKey, secretKey } = await ml_dsa65.keygen();

// Sign a message
const message = new TextEncoder().encode('Transfer $100 to Alice');
const signature = await ml_dsa65.sign(secretKey, message);

// Verify the signature
const valid = await ml_dsa65.verify(publicKey, message, signature);
console.log('Valid:', valid); // true

// Signing with context (optional, must match during verification)
const context = new TextEncoder().encode('payment-v1');
const sig2 = await ml_dsa65.sign(secretKey, message, context);
await ml_dsa65.verify(publicKey, message, sig2, context); // true
await ml_dsa65.verify(publicKey, message, sig2);           // false (context mismatch)
```

### CommonJS

```javascript
const { init, ml_kem768, ml_dsa65 } = require('fips-crypto');

async function main() {
  await init();

  // Key encapsulation
  const { publicKey, secretKey } = await ml_kem768.keygen();
  const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);
  const recovered = await ml_kem768.decapsulate(secretKey, ciphertext);

  // Digital signature
  const { publicKey: pk, secretKey: sk } = await ml_dsa65.keygen();
  const msg = Buffer.from('Hello');
  const sig = await ml_dsa65.sign(sk, msg);
  console.log('Signature valid:', await ml_dsa65.verify(pk, msg, sig));
}

main();
```

### Error Handling

```typescript
import { init, ml_kem768, ml_dsa65, FipsCryptoError } from 'fips-crypto';

await init();

try {
  await ml_kem768.encapsulate(new Uint8Array(100)); // wrong key length
} catch (error) {
  if (error instanceof FipsCryptoError) {
    console.log(error.code);    // 'INVALID_KEY_LENGTH'
    console.log(error.message); // 'Invalid public key length: expected 1184, got 100'
  }
}
```

---

## API Reference

### Initialization

#### `init(): Promise<void>`

Initialize the WASM module. Must be called before using any cryptographic functions. WASM modules must be loaded asynchronously; `init()` is a one-time cost at application startup.

- Safe to call multiple times (subsequent calls are no-ops)
- Safe to call concurrently (parallel calls share the same initialization promise)
- Throws `FipsCryptoError` with code `WASM_NOT_INITIALIZED` if the WASM module fails to load

```typescript
import { init } from 'fips-crypto';
await init();
```

**Framework integration patterns:**

```typescript
// Express / Fastify — initialize at server startup
import { init } from 'fips-crypto';
await init();
app.listen(3000);

// Next.js — initialize in instrumentation hook (instrumentation.ts)
export async function register() {
  const { init } = await import('fips-crypto');
  await init();
}
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

### ML-DSA (Digital Signatures)

#### `ml_dsa44 | ml_dsa65 | ml_dsa87`

Each ML-DSA variant provides the following methods:

##### `keygen(seed?: Uint8Array): Promise<MlDsaKeyPair>`

Generate a signing key pair.

- `seed` (optional): 32-byte seed for deterministic generation
- Returns: `{ publicKey: Uint8Array, secretKey: Uint8Array }`
- Throws: `INVALID_SEED_LENGTH` if seed is provided but not exactly 32 bytes

##### `sign(secretKey: Uint8Array, message: Uint8Array, context?: Uint8Array): Promise<Uint8Array>`

Sign a message.

- `secretKey`: Your signing key
- `message`: Message to sign (arbitrary length)
- `context` (optional): Context string (max 255 bytes, must match during verification)
- Returns: Signature bytes
- Throws: `INVALID_KEY_LENGTH` if secret key has wrong length

##### `verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array, context?: Uint8Array): Promise<boolean>`

Verify a signature.

- `publicKey`: Signer's verification key
- `message`: Original message
- `signature`: Signature to verify
- `context` (optional): Context string (must match the context used during signing)
- Returns: `true` if signature is valid, `false` otherwise
- Throws: `INVALID_KEY_LENGTH` if public key has wrong length
- Throws: `INVALID_SIGNATURE_LENGTH` if signature has wrong length

##### `params: MlDsaParams`

Parameter set information:

```typescript
{
  name: 'ML-DSA-65',
  securityCategory: 3,
  publicKeyBytes: 1952,
  secretKeyBytes: 4032,
  signatureBytes: 3309
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
| `npm run verify:integrity` | Verify WASM checksums |
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
| ML-DSA-65     | Cat. 3   | 1,952 B    | 4,032 B    | 3,309 B   |
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
- **Input Validation**: All key, ciphertext, seed, and context lengths are validated before processing
- **Memory Zeroization**: All secret key material is securely erased when no longer needed (via Rust `zeroize` crate)
- **Constant-Time Operations**: Critical operations avoid data-dependent timing and branching

For a detailed threat model, constant-time analysis, and zeroization boundaries, see [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).

### Supply Chain Integrity

Every build generates SHA-256 checksums of the WASM binary and JS binding files, stored in `dist/pkg/checksums.sha256`. This allows verification that the published package has not been tampered with.

```bash
# Verify checksums after install
npm run verify:integrity

# Or manually with standard tools
sha256sum node_modules/fips-crypto/dist/pkg/fips_crypto_wasm_bg.wasm
# Compare against node_modules/fips-crypto/dist/pkg/checksums.sha256
```

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

## Compliance Disclaimer

This library implements the **algorithm specifications** defined in FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA). It does **not** constitute a FIPS 140-2 or FIPS 140-3 validated cryptographic module.

- FIPS 203/204/205 define **algorithms** (what computations to perform)
- FIPS 140-2/140-3 define **module validation** (operational security requirements verified through CMVP)
- This library has **not** been submitted for CMVP validation

For government or regulated use cases that require FIPS 140 validation, confirm your compliance requirements independently before adopting this library.

---

## Standards Compliance

This library implements algorithms standardized by NIST:

- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM (August 2024)
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA (August 2024)
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) - SLH-DSA (August 2024)

### Compliance Verification

**ML-KEM (FIPS 203)**: Verified through Known Answer Tests (KAT) — pre-generated key pairs, ciphertexts, and shared secrets from an independent implementation are included as static test vectors. Our library must successfully decapsulate each ciphertext and recover the identical shared secret. Covers all three parameter sets.

**ML-DSA (FIPS 204)**: Verified through cross-implementation testing — signatures and keys generated by an independent FIPS 204 implementation are included as static test vectors. Our library must verify external signatures and produce signatures that the external implementation can verify. Additionally tested: corrupted signature rejection, context mismatch detection, cross-key failure, and signature non-determinism.

**Test coverage**: 543 JavaScript/TypeScript tests + 153 Rust unit tests. Coverage thresholds enforced at 99% statements, 99% functions, 97% branches, 99% lines. Safeguard tests protect against cross-algorithm key mixing, boundary value errors, input type violations, and API contract regressions.

The Rust implementation includes detailed references to specific FIPS algorithm numbers in source code comments.

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
