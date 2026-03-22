# Security Model

This document describes what fips-crypto protects against, how, and what it does not guarantee.

## Threat Model

fips-crypto is designed to protect against:

- **Remote timing attacks**: An attacker measuring response times over a network to infer secret key material.
- **Passive eavesdroppers**: An attacker intercepting public keys and ciphertexts on the wire, including adversaries with access to future quantum computers.
- **Chosen-ciphertext attacks**: An attacker submitting crafted ciphertexts to an ML-KEM decapsulation oracle to learn the secret key.

fips-crypto does **not** protect against:

- **Same-host side-channel attacks**: An attacker running code on the same machine may observe cache timing, power consumption, or electromagnetic emissions. WASM runtimes do not guarantee constant-time execution at the hardware level.
- **Spectre-class attacks**: Speculative execution vulnerabilities in the WASM engine or CPU.
- **Memory forensics**: After process termination, WASM linear memory pages may remain in swap or core dumps.
- **Compromised runtime**: If the JavaScript engine, WASM runtime, or operating system is compromised, no application-level defense helps.

## Constant-Time Operations

All security-critical computations in the Rust core avoid data-dependent branching and memory access patterns:

### ML-KEM (FIPS 203)

- **NTT/inverse NTT**: Fixed iteration count, no secret-dependent branches (`rust/src/primitives/ntt.rs`)
- **Polynomial arithmetic**: Barrett reduction and Montgomery multiplication with fixed execution paths
- **Decapsulation comparison**: Constant-time byte comparison of re-encrypted ciphertext vs received ciphertext, preventing timing leaks on valid/invalid ciphertexts
- **Implicit rejection**: On decapsulation failure, a pseudorandom shared secret is derived from the secret key and ciphertext rather than returning an error, preventing chosen-ciphertext distinguishing attacks
- **Secret selection**: Constant-time conditional select between the real shared secret and the rejection value, with no branching on the comparison result

### ML-DSA (FIPS 204)

- **NTT/inverse NTT**: ML-DSA-specific NTT over Z_q (q = 8,380,417) with fixed iteration structure (`rust/src/primitives/ntt.rs`)
- **Polynomial decompose/rounding**: Power2Round, Decompose, HighBits, LowBits, MakeHint, UseHint — all operate on each coefficient independently with no early exits (`rust/src/ml_dsa/polynomial.rs`)
- **Rejection sampling**: ExpandA, ExpandS, ExpandMask, SampleInBall use deterministic SHAKE-based expansion (`rust/src/ml_dsa/sampling.rs`)
- **Signing loop**: The rejection loop in signing does reveal the number of iterations (this is inherent to ML-DSA's design and specified in FIPS 204)

### SLH-DSA (FIPS 205)

- **Hash-based design**: SLH-DSA is based entirely on hash functions (SHA-256/SHA-512/SHAKE-256), with no algebraic operations. Timing depends only on the parameter set, not on secret data.
- **WOTS+ chain computation**: Fixed number of hash iterations per chain, determined by the message digest (not by secret keys)
- **FORS tree construction**: Fixed tree height and width, no secret-dependent branching
- **Hypertree traversal**: Fixed number of layers and per-layer tree height
- **PRF and tweakable hash**: All hash calls use the same input size per address type, preventing length-based timing leaks

### Limitations

WASM constant-time guarantees depend on the engine:

- **V8 (Node.js, Chrome)**: Generally preserves constant-time patterns from WASM, but JIT compilation and garbage collection pauses can introduce noise.
- **SpiderMonkey (Firefox)**: Similar behavior to V8.
- **Hardware**: The CPU itself may have variable-time instructions (e.g., some ARM processors have variable-time multiplication). Rust's compiler backend (LLVM) may also transform constant-time code in unexpected ways.

These are inherent limitations of running cryptography in a managed runtime. For the strongest side-channel guarantees, use a native library with hardware-specific constant-time validation.

## Memory Zeroization

### What is zeroized

All Rust structs containing secret key material derive `Zeroize` and `ZeroizeOnDrop` from the [zeroize](https://crates.io/crates/zeroize) crate:

- **ML-KEM key pairs**: Secret key bytes are overwritten with zeros when the Rust struct is dropped
- **ML-KEM encapsulation results**: Shared secret is zeroized on drop
- **ML-DSA key pairs**: Same zeroize-on-drop behavior
- **ML-DSA intermediate buffers**: Seed material (xi, rho', K) and signing intermediates (k_bytes, rnd, rho'') are explicitly zeroized before function return
- **SLH-DSA key pairs**: Same zeroize-on-drop behavior
- **SLH-DSA keygen intermediates**: Key material buffer is zeroized after extracting components

### What is NOT zeroized

- **JavaScript `Uint8Array` copies**: When WASM returns a secret key or shared secret to JavaScript, the bytes are copied into a `Uint8Array` in JS heap memory. The Rust side zeroizes its copy, but the JS copy is subject to garbage collection — there is no reliable way to zeroize it from JS, and the GC may have already copied the data internally.
- **WASM linear memory pages**: After WASM memory is freed but before the page is reclaimed by the OS, secret bytes may remain in the process's address space.
- **Swap and core dumps**: Neither Rust nor WASM can call `mlock()` to prevent pages from being written to disk.

### Recommendations

- For the highest secret handling assurance, minimize the lifetime of secret key `Uint8Array` objects in JavaScript. Overwrite them manually with zeros when done (acknowledging this is best-effort due to GC).
- If your threat model requires `mlock` or secure memory allocators, use a native crypto library instead of WASM.

## Random Number Generation

The Rust core uses the [getrandom](https://crates.io/crates/getrandom) crate with the `js` feature, which delegates to:

- **Node.js**: `crypto.getRandomValues()` (backed by the OS CSPRNG via OpenSSL or BoringSSL)
- **Browsers**: `crypto.getRandomValues()` (Web Crypto API, backed by the OS CSPRNG)

The library does not implement its own PRNG. All randomness comes from the platform's cryptographically secure random number generator.

Both ML-KEM and ML-DSA support optional deterministic seeds for testing and reproducibility. When a seed is provided, the algorithm's internal SHAKE-based expansion is used instead of `getrandom`. This is useful for test vector verification but should not be used in production unless you have a specific protocol requirement.

## Supply Chain Integrity

### Build-time checksums

Every build generates SHA-256 checksums of the WASM binary and JS binding files (`checksums.sha256`). These checksums are included in the published npm package.

### Verification

```bash
npm run verify:integrity
```

This compares the actual file hashes against the stored checksums. Any mismatch indicates tampering or corruption.

### npm Provenance

Releases published via GitHub Actions use npm's `--provenance` flag, which creates a [Sigstore](https://www.sigstore.dev/) attestation linking the published package to the specific GitHub Actions workflow run, commit SHA, and repository. This is visible as a "Provenance" badge on the npm package page.

### Checksums vs. Provenance: Threat Boundaries

**Checksums** (`checksums.sha256`) protect against **post-publish corruption**: if a CDN or mirror serves modified files, the checksums will mismatch. However, checksums are included inside the package itself — an attacker who compromises the publish step can regenerate checksums to match their tampered binaries. Checksums alone **cannot** detect a compromised build pipeline or stolen npm token.

**npm Provenance** (Sigstore attestation) protects against **build-origin spoofing**: the attestation cryptographically links the published tarball to a specific GitHub Actions workflow run, commit SHA, and repository. Even if an attacker steals the npm publish token, they cannot forge a valid Sigstore attestation from the legitimate GitHub Actions environment.

To verify provenance:

```bash
npm audit signatures
```

**Defense in depth**: Use both. Checksums catch accidental corruption and CDN issues. Provenance catches deliberate supply chain attacks on the publish step. Neither protects against a compromised source repository (e.g., a malicious commit merged to `main`). For that, rely on code review and branch protection rules.

| Threat | Checksums | Provenance |
|--------|-----------|------------|
| CDN/mirror corruption | Detects | No |
| Stolen npm token | No | Detects |
| Compromised CI environment | No | No |
| Malicious source commit | No | No |
