# Contributing to fips-crypto

This document describes the development workflow for `fips-crypto`.

## Development Setup

### Prerequisites

1. Rust stable
   macOS/Linux: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
   Windows: install [rustup-init.exe](https://rustup.rs/)
2. WebAssembly target: `rustup target add wasm32-unknown-unknown`
3. `wasm-pack`: `cargo install wasm-pack`
4. Node.js 20+

### Getting Started

```bash
git clone https://github.com/<your-username>/fips-crypto.git
cd fips-crypto
npm install
npm run build
npm test
```

## Common Commands

| Command | Description |
|---------|-------------|
| `npm run build` | Build Rust/WASM artifacts and TypeScript output |
| `npm test` | Run the Vitest suite |
| `npm run test:coverage` | Run tests with coverage |
| `npm run test:pack` | Smoke-test the packed npm artifact |
| `npm run bench` | Run benchmarks |
| `npm run lint` | Run ESLint |
| `npm run verify:integrity` | Verify local built artifact checksums |
| `cargo test` | Run Rust tests |

## Pull Request Checklist

1. `npm run build`
2. `npm test`
3. `npm run test:pack` for packaging-sensitive changes
4. `cargo test` for Rust changes
5. `npm run lint`

## Process

1. Fork the repository.
2. Create a feature branch from `dev`.
3. Make the change.
4. Run the relevant checks.
5. Open a pull request against `dev`.

For larger changes, open an issue first.

## Cryptographic Changes

Changes to `rust/src/` need extra care:

- Reference the relevant FIPS algorithm or section.
- Preserve constant-time structure in security-critical paths.
- Zeroize secret material and sensitive intermediate buffers where practical.
- Add independent-vector or cross-implementation coverage when changing algorithm behavior.
- Avoid dependency changes unless there is a clear need.

## Project Structure

```text
fips-crypto/
|-- rust/src/
|   |-- ml_kem/
|   |-- ml_dsa/
|   |-- slh_dsa/
|   `-- primitives/
|-- src/
|   |-- index.ts
|   |-- auto.ts
|   |-- ml-kem.ts
|   |-- ml-dsa.ts
|   |-- slh-dsa.ts
|   `-- types.ts
|-- tests/
|   |-- unit/
|   `-- vectors/
|-- docs/
|-- scripts/
`-- dist/
```

## Security

Security-related reports should follow the process in [SECURITY.md](SECURITY.md).
