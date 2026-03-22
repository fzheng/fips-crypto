# Contributing to fips-crypto

Thank you for your interest in contributing to fips-crypto! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites

1. **Rust** (stable toolchain)
   - macOS/Linux: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
   - Windows: Download [rustup-init.exe](https://rustup.rs/)

2. **WebAssembly target**: `rustup target add wasm32-unknown-unknown`

3. **wasm-pack**: `cargo install wasm-pack`

4. **Node.js 18+**: Download from [nodejs.org](https://nodejs.org/) or use a version manager

### Getting Started

```bash
# Fork and clone the repository
git clone https://github.com/<your-username>/fips-crypto.git
cd fips-crypto

# Install dependencies
npm install

# Build WASM + TypeScript
npm run build

# Run tests
npm test
```

## Available Commands

| Command | Description |
|---------|-------------|
| `npm run build` | Build WASM module and TypeScript |
| `npm test` | Run test suite |
| `npm run test:coverage` | Run tests with coverage report |
| `npm run bench` | Run benchmarks |
| `npm run lint` | Run ESLint |
| `npm run verify:integrity` | Verify WASM binary checksums |
| `cargo test` | Run Rust unit tests |

## Submitting Changes

### Pull Request Requirements

1. **All tests pass**: `npm test` and `cargo test`
2. **Lint clean**: `npm run lint`
3. **Coverage maintained**: Coverage thresholds are enforced (99% statements/functions/lines, 97% branches)
4. **Clear commit messages**: Describe what changed and why

### Process

1. Fork the repository
2. Create a feature branch from `dev`
3. Make your changes
4. Ensure all checks pass
5. Submit a pull request to `dev`

For major changes, please open an issue first to discuss the proposed approach.

### Cryptographic Changes

Changes to cryptographic implementations require extra care:

- Reference the specific FIPS algorithm/section being implemented
- Include test vector verification against an independent implementation
- Do not introduce new dependencies without discussion
- Maintain constant-time behavior in security-critical code paths
- Ensure `zeroize` is used for all secret key material

## Project Structure

```
fips-crypto/
├── rust/src/           # Rust cryptographic implementations
│   ├── ml_kem/         # FIPS 203 ML-KEM
│   ├── ml_dsa/         # FIPS 204 ML-DSA
│   ├── slh_dsa/        # FIPS 205 SLH-DSA
│   └── primitives/     # Shared primitives (NTT, polynomial, SHA3)
├── src/                # TypeScript wrappers
│   ├── index.ts        # Main entry point
│   ├── auto.ts         # Auto-init entry point (no init() needed)
│   ├── ml-kem.ts       # ML-KEM wrapper
│   ├── ml-dsa.ts       # ML-DSA wrapper
│   ├── slh-dsa.ts      # SLH-DSA wrapper
│   └── types.ts        # Type definitions
├── tests/              # Test suite
│   ├── unit/           # Unit tests
│   └── vectors/        # Compliance test vectors
├── benchmarks/         # Performance benchmarks
├── scripts/            # Build/verification scripts
└── dist/               # Built output (not in source)
```

## Code of Conduct

Be respectful, constructive, and focused on making the project better. Security-related discussions should follow responsible disclosure practices outlined in [SECURITY.md](SECURITY.md).
