# fips-crypto

High-performance post-quantum cryptography for JavaScript and TypeScript, powered by Rust + WebAssembly.

[![CI](https://github.com/fzheng/fips-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/fzheng/fips-crypto/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/fips-crypto.svg)](https://www.npmjs.com/package/fips-crypto)
[![npm downloads](https://img.shields.io/npm/dw/fips-crypto.svg)](https://www.npmjs.com/package/fips-crypto)
[![codecov](https://codecov.io/gh/fzheng/fips-crypto/graph/badge.svg?token=X6HH8RWTDZ)](https://codecov.io/gh/fzheng/fips-crypto)
[![license](https://img.shields.io/npm/l/fips-crypto.svg?color=blue)](https://github.com/fzheng/fips-crypto/blob/main/LICENSE)
[![FIPS 203](https://img.shields.io/badge/FIPS%20203-ML--KEM-blue)](https://csrc.nist.gov/pubs/fips/203/final)
[![FIPS 204](https://img.shields.io/badge/FIPS%20204-ML--DSA-blue)](https://csrc.nist.gov/pubs/fips/204/final)
[![FIPS 205](https://img.shields.io/badge/FIPS%20205-SLH--DSA-blue)](https://csrc.nist.gov/pubs/fips/205/final)
[![provenance](https://img.shields.io/badge/provenance-sigstore-green)](https://www.npmjs.com/package/fips-crypto)

> **Note:** This package implements the algorithm specifications in FIPS 203, FIPS 204, and FIPS 205. It is **not** a FIPS 140-2 or FIPS 140-3 validated cryptographic module. If your compliance framework requires CMVP-validated modules, this library does not satisfy that requirement.

## Why post-quantum cryptography matters

Quantum computers running Shor's algorithm will break the classical cryptography that secures today's systems:

- **ECDSA** (Bitcoin, Ethereum, TLS) &mdash; private keys derived from public keys
- **RSA** (HTTPS, email, code signing) &mdash; factored in polynomial time
- **ECDH/X25519** (key exchange) &mdash; same elliptic curve vulnerability

NIST finalized three post-quantum standards in 2024 (FIPS 203, 204, 205) to replace these vulnerable primitives. fips-crypto brings all three to JavaScript. See the [quantum-safe wallet example](examples/quantum-safe-wallet.mjs) for a demo of replacing the ECDSA signature primitive in a cryptocurrency-style workflow.

## Why fips-crypto

- **Standards-focused** &mdash; implements NIST [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) (ML-KEM), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) (ML-DSA), and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) (SLH-DSA)
- **Rust + WebAssembly core** &mdash; constant-time-oriented critical paths with Rust-side zeroization of secret material
- **TypeScript-first** &mdash; full type definitions, explicit input validation, clear error codes
- **Tested and benchmarked** &mdash; 970+ tests, 99%+ coverage, cross-implementation compliance vectors
- **Flexible** &mdash; ESM, CommonJS, auto-init; Node.js CI-tested, browser-compatible via bundlers

## Try it now

```bash
npm install fips-crypto
```

```ts
import { ml_kem768, ml_dsa65, slh_dsa_shake_192f } from 'fips-crypto/auto';

// Key encapsulation (ML-KEM)
const { publicKey, secretKey } = await ml_kem768.keygen();
const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);
const recovered = await ml_kem768.decapsulate(secretKey, ciphertext);

// Digital signatures (ML-DSA)
const message = new TextEncoder().encode('hello post-quantum world');
const keys = await ml_dsa65.keygen();
const signature = await ml_dsa65.sign(keys.secretKey, message);
const valid = await ml_dsa65.verify(keys.publicKey, message, signature);

// Hash-based signatures (SLH-DSA)
const slhKeys = await slh_dsa_shake_192f.keygen();
const slhSig = await slh_dsa_shake_192f.sign(slhKeys.secretKey, message);
const slhValid = await slh_dsa_shake_192f.verify(slhKeys.publicKey, message, slhSig);
```

See the [fips-crypto-demo](https://github.com/fzheng/fips-crypto-demo) for an interactive app, or browse the [examples/](examples/) folder for ready-to-run scripts:

- [Key Encapsulation](examples/key-encapsulation.mjs) — ML-KEM key exchange
- [Digital Signatures](examples/digital-signatures.mjs) — ML-DSA signing with context binding
- [Hash-Based Signatures](examples/hash-based-signatures.mjs) — SLH-DSA signing
- [Quantum-Safe Wallet](examples/quantum-safe-wallet.mjs) — ML-DSA signature replacement in a crypto-style workflow
- [CommonJS Usage](examples/commonjs-usage.cjs) — `require()` with auto-init

## Performance

Benchmarked on Node.js with Vitest bench (`npm run bench`). Results are operations per second (higher is better).

### ML-KEM (FIPS 203)

| Operation | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|-----------|-----------|-----------|------------|
| keygen | 32,367 ops/s | 20,233 ops/s | 13,159 ops/s |
| encapsulate | 28,805 ops/s | 19,790 ops/s | 13,832 ops/s |
| decapsulate | 26,196 ops/s | 17,191 ops/s | 12,370 ops/s |

### ML-DSA (FIPS 204)

| Operation | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|-----------|----------|----------|----------|
| keygen | 10,718 ops/s | 7,428 ops/s | 4,315 ops/s |
| sign | 3,625 ops/s | 2,073 ops/s | 1,754 ops/s |
| verify | 14,052 ops/s | 8,355 ops/s | 5,165 ops/s |

### SLH-DSA (FIPS 205) &mdash; fast variants

| Operation | SHA2-128f | SHAKE-128f | SHA2-192f | SHAKE-192f |
|-----------|----------|-----------|----------|-----------|
| keygen | 694 ops/s | 450 ops/s | 463 ops/s | 305 ops/s |
| sign | 29 ops/s | 18 ops/s | 18 ops/s | 11 ops/s |
| verify | 478 ops/s | 312 ops/s | 316 ops/s | 218 ops/s |

<details>
<summary>Reproduce these benchmarks</summary>

```bash
git clone https://github.com/fzheng/fips-crypto.git
cd fips-crypto
npm install && npm run build
npm run bench
```

Results will vary by hardware and Node.js version. The numbers above are representative, not a guarantee.
</details>

## Supported algorithms

### ML-KEM (FIPS 203)

- `ml_kem512`
- `ml_kem768` &mdash; recommended
- `ml_kem1024`

### ML-DSA (FIPS 204)

- `ml_dsa44`
- `ml_dsa65` &mdash; recommended
- `ml_dsa87`

### SLH-DSA (FIPS 205)

All 12 parameter sets:

- SHA2: `slh_dsa_sha2_128s`, `slh_dsa_sha2_128f`, `slh_dsa_sha2_192s`, `slh_dsa_sha2_192f`, `slh_dsa_sha2_256s`, `slh_dsa_sha2_256f`
- SHAKE: `slh_dsa_shake_128s`, `slh_dsa_shake_128f`, `slh_dsa_shake_192s`, `slh_dsa_shake_192f`, `slh_dsa_shake_256s`, `slh_dsa_shake_256f`

`f` variants sign faster with larger signatures. `s` variants produce smaller signatures but sign more slowly.

## Choosing parameter sets

| Use case | Recommended |
|----------|-------------|
| Key encapsulation (general) | `ml_kem768` |
| Digital signatures (lattice-based) | `ml_dsa65` |
| Hash-based signatures (balanced) | `slh_dsa_sha2_192f` or `slh_dsa_shake_192f` |
| Smallest hash-based signatures | `slh_dsa_sha2_128s` or `slh_dsa_shake_128s` |

## Installation

```bash
npm install fips-crypto
```

### Entrypoints

| Import path | Use case |
|-------------|----------|
| `fips-crypto/auto` | Lazy initialization on first use (recommended) |
| `fips-crypto` | Explicit `init()` for precise control |
| `fips-crypto/ml-kem` | ML-KEM-only import surface |
| `fips-crypto/ml-dsa` | ML-DSA-only import surface |
| `fips-crypto/slh-dsa` | SLH-DSA-only import surface |

### Runtime support

| Runtime | Status | Notes |
|---------|--------|-------|
| Node.js 20+ | Supported | CI tested on Linux, macOS, and Windows |
| Browsers | Compatible | Requires a bundler with WASM support; not yet CI-validated |
| Bun | Untested | Community validation welcome |
| Deno | Untested | Community validation welcome |

## API

### Initialization

`fips-crypto/auto` initializes lazily on first use (recommended). Use `import { init } from 'fips-crypto'` and call `await init()` if you need explicit control over when WASM loads.

### ML-KEM

```ts
keygen(seed?: Uint8Array)           // seed: exactly 64 bytes
encapsulate(publicKey, seed?)       // seed: exactly 32 bytes
decapsulate(secretKey, ciphertext)
params                              // { name, publicKeyBytes, ... }
```

### ML-DSA

```ts
keygen(seed?: Uint8Array)                          // seed: exactly 32 bytes
sign(secretKey, message, context?: Uint8Array)     // context: max 255 bytes
verify(publicKey, message, signature, context?)
params
```

### SLH-DSA

```ts
keygen(seed?: Uint8Array)                          // seed: 48/72/96 bytes by security level
sign(secretKey, message, context?: Uint8Array)     // context: max 255 bytes
verify(publicKey, message, signature, context?)
params
```

### Errors

Invalid inputs throw `FipsCryptoError` with codes: `WASM_NOT_INITIALIZED`, `INVALID_KEY_LENGTH`, `INVALID_CIPHERTEXT_LENGTH`, `INVALID_SIGNATURE_LENGTH`, `INVALID_SEED_LENGTH`, `INVALID_CONTEXT_LENGTH`.

## Algorithm parameters

### ML-KEM

| Parameter set | Security | Public key | Secret key | Ciphertext | Shared secret |
|---------------|----------|------------|------------|------------|---------------|
| ML-KEM-512 | Cat 1 | 800 B | 1632 B | 768 B | 32 B |
| ML-KEM-768 | Cat 3 | 1184 B | 2400 B | 1088 B | 32 B |
| ML-KEM-1024 | Cat 5 | 1568 B | 3168 B | 1568 B | 32 B |

### ML-DSA

| Parameter set | Security | Public key | Secret key | Signature |
|---------------|----------|------------|------------|-----------|
| ML-DSA-44 | Cat 2 | 1312 B | 2560 B | 2420 B |
| ML-DSA-65 | Cat 3 | 1952 B | 4032 B | 3309 B |
| ML-DSA-87 | Cat 5 | 2592 B | 4896 B | 4627 B |

### SLH-DSA

| Parameter set | Security | Public key | Secret key | Signature |
|---------------|----------|------------|------------|-----------|
| SLH-DSA-SHA2-128s | 128-bit | 32 B | 64 B | 7,856 B |
| SLH-DSA-SHA2-128f | 128-bit | 32 B | 64 B | 17,088 B |
| SLH-DSA-SHA2-192s | 192-bit | 48 B | 96 B | 16,224 B |
| SLH-DSA-SHA2-192f | 192-bit | 48 B | 96 B | 35,664 B |
| SLH-DSA-SHA2-256s | 256-bit | 64 B | 128 B | 29,792 B |
| SLH-DSA-SHA2-256f | 256-bit | 64 B | 128 B | 49,856 B |
| SLH-DSA-SHAKE-128s | 128-bit | 32 B | 64 B | 7,856 B |
| SLH-DSA-SHAKE-128f | 128-bit | 32 B | 64 B | 17,088 B |
| SLH-DSA-SHAKE-192s | 192-bit | 48 B | 96 B | 16,224 B |
| SLH-DSA-SHAKE-192f | 192-bit | 48 B | 96 B | 35,664 B |
| SLH-DSA-SHAKE-256s | 256-bit | 64 B | 128 B | 29,792 B |
| SLH-DSA-SHAKE-256f | 256-bit | 64 B | 128 B | 49,856 B |

## Security

- Rust core keeps security-critical operations branch-regular and fixed-shape
- ML-KEM implements implicit rejection during decapsulation
- Secret-bearing Rust structs and intermediate buffers are zeroized on drop
- JS `Uint8Array` copies are subject to garbage collection &mdash; not reliably zeroized
- WASM does not provide the same side-channel guarantees as a hardened native library

For the full threat model, zeroization boundaries, and side-channel analysis, see [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).

## Supply chain integrity

```bash
npx fips-crypto-verify-integrity   # verify WASM checksums after install
npm audit signatures               # verify npm provenance via Sigstore
```

Every build includes SHA-256 checksums for WASM artifacts. Provenance links each published package to a specific GitHub Actions workflow run. See [SECURITY.md](SECURITY.md) for details.

## Validation and testing

- **970+** tests (748 JavaScript/TypeScript + 225 Rust)
- **99%+** coverage (statements, functions, branches, lines)
- Cross-implementation compliance vectors for all algorithm families
- Packed-artifact smoke tests in CI

## Building from source

```bash
# Prerequisites: Rust stable, wasm-pack, Node.js 20+
rustup target add wasm32-unknown-unknown

git clone https://github.com/fzheng/fips-crypto.git
cd fips-crypto
npm install
npm run build
npm test
```

| Command | Description |
|---------|-------------|
| `npm run build` | Build Rust/WASM + TypeScript |
| `npm test` | Run tests |
| `npm run test:coverage` | Tests with coverage |
| `cargo test` | Rust tests |
| `npm run bench` | Benchmarks |
| `npm run lint` | ESLint |

## Standards

- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) &mdash; ML-KEM
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) &mdash; ML-DSA
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) &mdash; SLH-DSA
- [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/final) &mdash; Migration guidance

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

MIT

---

If this library is useful to your project, please consider giving it a star on GitHub.
