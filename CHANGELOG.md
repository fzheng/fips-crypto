# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-03-20

### Added
- **ML-DSA (FIPS 204)** full implementation: ML-DSA-44, ML-DSA-65, ML-DSA-87
  - Key generation, signing, and verification
  - Context parameter support (max 255 bytes)
  - Seed-based deterministic key generation
- ML-DSA compliance tests using pre-generated vectors from an independent FIPS 204 implementation
- Supply chain integrity protection: SHA-256 checksums for all WASM/JS binaries
- `npm run verify:integrity` command to verify package integrity after install
- Property-based tests with fast-check for ML-KEM
- Concurrent initialization safety for `init()` / `initMlKem()` / `initMlDsa()`
- Safeguard tests for cross-algorithm isolation and boundary conditions
- ESLint configuration

### Changed
- Coverage thresholds raised to 99/99/97/99 (statements/functions/branches/lines)
- Build scripts now use `shx` for cross-platform compatibility (Windows/macOS/Linux)

### Fixed
- ML-DSA-65 signature size corrected from 3293 to 3309 bytes per FIPS 204
- Seed length validation added to ML-KEM keygen (64 bytes) and encapsulate (32 bytes)
- Post-build patch for Socket.dev false-positive eval detection in wasm-bindgen output

## [0.4.0] - 2026-03-15

### Added
- Cross-platform CI: Ubuntu, macOS, and Windows with Node.js 18, 20, 22
- Vitest setup file polyfilling `globalThis.crypto` for v8 coverage workers
- Codecov action upgraded to v5

### Changed
- License changed from GPL-3.0 to MIT
- Coverage thresholds updated

## [0.3.0] - 2026-03-01

### Added
- GitHub Actions CI with Rust and JS test jobs
- Codecov integration for code coverage tracking
- 18 new validation tests, coverage from 96.1% to 99.61%

## [0.2.2] - 2026-02-20

### Fixed
- Missing `pkg/` directory in published npm package

## [0.2.1] - 2026-02-19

### Fixed
- Missing WASM binaries in published npm package
- Various bug fixes

## [0.2.0] - 2026-02-15

### Added
- FIPS 203 KAT (Known Answer Test) vector compliance testing
- Comprehensive documentation and tests

### Fixed
- ML-KEM cryptographic implementation bugs

## [0.1.0] - 2026-02-01

### Added
- Initial release
- ML-KEM (FIPS 203) implementation: ML-KEM-512, ML-KEM-768, ML-KEM-1024
- Key generation, encapsulation, and decapsulation
- Rust/WASM cryptographic core
- TypeScript/JavaScript wrappers with ESM and CJS support
- SLH-DSA parameter set definitions (stubs)

[0.5.0]: https://github.com/fzheng/fips-crypto/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/fzheng/fips-crypto/compare/0.3.0...v0.4.0
[0.3.0]: https://github.com/fzheng/fips-crypto/compare/0.2.2...0.3.0
[0.2.2]: https://github.com/fzheng/fips-crypto/compare/v0.2.1...0.2.2
[0.2.1]: https://github.com/fzheng/fips-crypto/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/fzheng/fips-crypto/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/fzheng/fips-crypto/releases/tag/v0.1.0
