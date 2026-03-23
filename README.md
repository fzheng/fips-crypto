# fips-crypto

[![CI](https://github.com/fzheng/fips-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/fzheng/fips-crypto/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/fips-crypto.svg)](https://www.npmjs.com/package/fips-crypto)
[![license](https://img.shields.io/npm/l/fips-crypto.svg?color=blue)](https://github.com/fzheng/fips-crypto/blob/main/LICENSE)
[![codecov](https://codecov.io/gh/fzheng/fips-crypto/graph/badge.svg?token=X6HH8RWTDZ)](https://codecov.io/gh/fzheng/fips-crypto)
[![FIPS 203](https://img.shields.io/badge/FIPS%20203-ML--KEM-blue)](https://csrc.nist.gov/pubs/fips/203/final)
[![FIPS 204](https://img.shields.io/badge/FIPS%20204-ML--DSA-blue)](https://csrc.nist.gov/pubs/fips/204/final)
[![FIPS 205](https://img.shields.io/badge/FIPS%20205-SLH--DSA-blue)](https://csrc.nist.gov/pubs/fips/205/final)

Rust/WASM implementations of NIST post-quantum cryptography algorithms for Node.js and bundler-based browser apps.

> This package implements the algorithm specifications in FIPS 203, FIPS 204, and FIPS 205.

## Why fips-crypto

- ML-KEM, ML-DSA, and SLH-DSA in one package
- ESM, CommonJS, and lazy auto-init entrypoints
- TypeScript-first API with explicit input-size and context validation
- Rust core with constant-time-oriented critical paths and Rust-side zeroization of secret material
- Built-in package integrity verification plus npm provenance support

## Supported algorithms

### ML-KEM (FIPS 203)

- `ml_kem512`
- `ml_kem768` - recommended default
- `ml_kem1024`

### ML-DSA (FIPS 204)

- `ml_dsa44`
- `ml_dsa65` - recommended default
- `ml_dsa87`

### SLH-DSA (FIPS 205)

All 12 parameter sets are implemented:

- SHA2: `slh_dsa_sha2_128s`, `slh_dsa_sha2_128f`, `slh_dsa_sha2_192s`, `slh_dsa_sha2_192f`, `slh_dsa_sha2_256s`, `slh_dsa_sha2_256f`
- SHAKE: `slh_dsa_shake_128s`, `slh_dsa_shake_128f`, `slh_dsa_shake_192s`, `slh_dsa_shake_192f`, `slh_dsa_shake_256s`, `slh_dsa_shake_256f`

`f` variants sign faster and produce larger signatures. `s` variants produce smaller signatures and sign more slowly.

## Installation

```bash
npm install fips-crypto
```

### Entrypoints

| Import path | Use case |
|-------------|----------|
| `fips-crypto` | Main ESM/CJS entrypoint with explicit `init()` |
| `fips-crypto/auto` | Lazy initialization on first use |
| `fips-crypto/ml-kem` | ML-KEM-only import surface |
| `fips-crypto/ml-dsa` | ML-DSA-only import surface |
| `fips-crypto/slh-dsa` | SLH-DSA-only import surface |

### Runtime support

| Runtime | Status | Notes |
|---------|--------|-------|
| Node.js 20+ | Supported | CI coverage on Linux, macOS, and Windows |
| Browsers | Supported | Requires a bundler/runtime that supports WASM module loading |
| Bun | Untested | Community validation welcome |
| Deno | Untested | Community validation welcome |

## Quick start

### Recommended: auto-init

```ts
import { ml_kem768, ml_dsa65 } from 'fips-crypto/auto';

const { publicKey, secretKey } = await ml_kem768.keygen();
const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);
const recovered = await ml_kem768.decapsulate(secretKey, ciphertext);

const message = new TextEncoder().encode('hello post-quantum world');
const { publicKey: verifyKey, secretKey: signKey } = await ml_dsa65.keygen();
const signature = await ml_dsa65.sign(signKey, message);
const valid = await ml_dsa65.verify(verifyKey, message, signature);
```

### Explicit init

```ts
import { init, ml_kem768 } from 'fips-crypto';

await init();

const { publicKey, secretKey } = await ml_kem768.keygen();
const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);
const recovered = await ml_kem768.decapsulate(secretKey, ciphertext);
```

### SLH-DSA example

```ts
import { slh_dsa_shake_192f } from 'fips-crypto/auto';

const { publicKey, secretKey } = await slh_dsa_shake_192f.keygen();
const message = new TextEncoder().encode('sign me');
const context = new TextEncoder().encode('example-v1');

const signature = await slh_dsa_shake_192f.sign(secretKey, message, context);
const valid = await slh_dsa_shake_192f.verify(publicKey, message, signature, context);
```

### CommonJS

```js
const { init, ml_kem768 } = require('fips-crypto');

async function main() {
  await init();
  const { publicKey, secretKey } = await ml_kem768.keygen();
  const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);
  const recovered = await ml_kem768.decapsulate(secretKey, ciphertext);
  console.log(sharedSecret.length, recovered.length);
}

main();
```

## API summary

### Initialization

- `init()` initializes the ML-KEM, ML-DSA, and SLH-DSA WASM modules.
- `fips-crypto/auto` skips the manual `init()` call and initializes lazily on first use.

### ML-KEM API

Each ML-KEM variant exposes:

- `keygen(seed?)`
- `encapsulate(publicKey, seed?)`
- `decapsulate(secretKey, ciphertext)`
- `params`

Seed sizes:

- `keygen(seed)`: exactly 64 bytes
- `encapsulate(publicKey, seed)`: exactly 32 bytes

### ML-DSA API

Each ML-DSA variant exposes:

- `keygen(seed?)`
- `sign(secretKey, message, context?)`
- `verify(publicKey, message, signature, context?)`
- `params`

Constraints:

- `keygen(seed)`: exactly 32 bytes
- `context`: at most 255 bytes

### SLH-DSA API

Each SLH-DSA variant exposes:

- `keygen(seed?)`
- `sign(secretKey, message, context?)`
- `verify(publicKey, message, signature, context?)`
- `params`

Seed sizes depend on the security level:

- 128-bit variants: 48-byte seed
- 192-bit variants: 72-byte seed
- 256-bit variants: 96-byte seed

`context` is limited to 255 bytes.

### Errors

Invalid inputs throw `FipsCryptoError` with codes such as:

- `WASM_NOT_INITIALIZED`
- `INVALID_KEY_LENGTH`
- `INVALID_CIPHERTEXT_LENGTH`
- `INVALID_SIGNATURE_LENGTH`
- `INVALID_SEED_LENGTH`
- `INVALID_CONTEXT_LENGTH`

## Choosing parameter sets

- Use `ml_kem768` for most KEM use cases.
- Use `ml_dsa65` for most lattice-based signature use cases.
- Use `slh_dsa_sha2_192f` or `slh_dsa_shake_192f` when you want hash-based signatures with balanced security/performance.
- Prefer `f` SLH-DSA variants when signing throughput matters.
- Prefer `s` SLH-DSA variants when signature size matters more than signing speed.

## Algorithm parameters

### ML-KEM

| Parameter set | Security category | Public key | Secret key | Ciphertext | Shared secret |
|---------------|-------------------|------------|------------|------------|---------------|
| ML-KEM-512 | 1 | 800 B | 1632 B | 768 B | 32 B |
| ML-KEM-768 | 3 | 1184 B | 2400 B | 1088 B | 32 B |
| ML-KEM-1024 | 5 | 1568 B | 3168 B | 1568 B | 32 B |

### ML-DSA

| Parameter set | Security category | Public key | Secret key | Signature |
|---------------|-------------------|------------|------------|-----------|
| ML-DSA-44 | 2 | 1312 B | 2560 B | 2420 B |
| ML-DSA-65 | 3 | 1952 B | 4032 B | 3309 B |
| ML-DSA-87 | 5 | 2592 B | 4896 B | 4627 B |

### SLH-DSA

| Parameter set | Security level | Public key | Secret key | Signature |
|---------------|----------------|------------|------------|-----------|
| SLH-DSA-SHA2-128s | 128-bit | 32 B | 64 B | 7856 B |
| SLH-DSA-SHA2-128f | 128-bit | 32 B | 64 B | 17088 B |
| SLH-DSA-SHA2-192s | 192-bit | 48 B | 96 B | 16224 B |
| SLH-DSA-SHA2-192f | 192-bit | 48 B | 96 B | 35664 B |
| SLH-DSA-SHA2-256s | 256-bit | 64 B | 128 B | 29792 B |
| SLH-DSA-SHA2-256f | 256-bit | 64 B | 128 B | 49856 B |
| SLH-DSA-SHAKE-128s | 128-bit | 32 B | 64 B | 7856 B |
| SLH-DSA-SHAKE-128f | 128-bit | 32 B | 64 B | 17088 B |
| SLH-DSA-SHAKE-192s | 192-bit | 48 B | 96 B | 16224 B |
| SLH-DSA-SHAKE-192f | 192-bit | 48 B | 96 B | 35664 B |
| SLH-DSA-SHAKE-256s | 256-bit | 64 B | 128 B | 29792 B |
| SLH-DSA-SHAKE-256f | 256-bit | 64 B | 128 B | 49856 B |

## Validation and testing

Current validation layers include:

- `718` JavaScript/TypeScript tests
- `225` Rust tests
- Coverage thresholds of 99% statements, 99% functions, 97% branches, and 99% lines
- Packed-artifact smoke tests in CI and the publish workflow

Validation scope by algorithm:

- ML-KEM: known-answer and cross-check style tests across all three parameter sets
- ML-DSA: cross-implementation vector verification across all three parameter sets, plus negative-path testing
- SLH-DSA: all 12 parameter sets are implemented and exercised by unit and safeguard tests; current cross-implementation vector coverage is for the 6 fast variants (`128f`, `192f`, `256f` for SHA2 and SHAKE)

If you change cryptographic behavior, extend both the Rust tests and the higher-level JS/TS tests, and add or update independent vectors where possible.

## Security notes

This package is intended for practical application use, but the security claims should be read in the right scope:

- The Rust core is written to keep security-critical operations branch-regular and fixed-shape where the algorithms require it.
- ML-KEM implements implicit rejection during decapsulation.
- Secret-bearing Rust structs and selected intermediate buffers are zeroized on drop or before return.
- JavaScript `Uint8Array` copies are not reliably zeroized; once secret material is copied into JS memory, garbage collection semantics apply.
- WASM does not provide the same-host side-channel guarantees as a hardened native cryptographic library.

For the full threat model, zeroization boundaries, and side-channel caveats, see [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).

## Supply chain integrity

Every build includes SHA-256 checksums for the published WASM and JS binding artifacts.

```bash
# Verify an installed package
npx fips-crypto-verify-integrity

# Verify from a package checkout after building
npm run verify:integrity
```

For provenance verification:

```bash
npm audit signatures
```

Checksums help detect post-publish corruption. Provenance helps confirm the package was built and published by the expected GitHub Actions workflow. See [SECURITY.md](SECURITY.md) and [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) for the threat boundaries of each layer.

## Building from source

### Prerequisites

1. Rust stable
2. `wasm32-unknown-unknown` target
3. `wasm-pack`
4. Node.js 20+

### Build and test

```bash
npm install
npm run build
npm test
cargo test
npm run test:pack
```

Useful commands:

| Command | Description |
|---------|-------------|
| `npm run build` | Build Rust/WASM artifacts and TypeScript output |
| `npm test` | Run the Vitest suite |
| `npm run test:coverage` | Run tests with coverage |
| `npm run test:pack` | Smoke-test the packed npm artifact |
| `cargo test` | Run Rust tests |
| `npm run bench` | Run benchmarks |
| `npm run lint` | Run ESLint |

More contributor workflow detail lives in [CONTRIBUTING.md](CONTRIBUTING.md).

## Standards

- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) - SLH-DSA

NIST migration guidance is tracked in [IR 8547](https://csrc.nist.gov/pubs/ir/8547/final).

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) if your change touches cryptographic behavior or disclosure-sensitive issues.

## License

MIT

