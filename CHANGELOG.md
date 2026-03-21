# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-03-20

### Added

**ML-DSA (FIPS 204) — full implementation**
- ML-DSA-44, ML-DSA-65, ML-DSA-87: key generation, signing, and verification
- Context parameter support (max 255 bytes per FIPS 204)
- Seed-based deterministic key generation (32-byte seeds)
- Rust implementation: NTT (q=8380417), polynomial arithmetic, ExpandA/ExpandS/ExpandMask/SampleInBall, FIPS 204 Algorithms 1-3
- 9 WASM bindings replacing ML-DSA stubs
- ML-DSA compliance tests using pre-generated vectors from an independent FIPS 204 implementation

**Supply chain integrity**
- SHA-256 checksums generated for all WASM/JS binaries at build time (`checksums.sha256`)
- `npm run verify:integrity` to verify package integrity after install
- npm publish workflow with Sigstore provenance (`.github/workflows/publish.yml`)

**Performance benchmarks**
- ML-KEM benchmark suite: keygen, encapsulate, decapsulate for all 3 variants
- ML-DSA benchmark suite: keygen, sign, verify for all 3 variants
- Performance results published in README
- Benchmark step added to CI with artifact upload

**Auto-init entry point**
- `import from 'fips-crypto/auto'` — no `init()` call needed, WASM loads lazily on first use
- New `./auto` export in package.json

**Documentation**
- SECURITY.md: vulnerability reporting policy, response timelines, scope
- CONTRIBUTING.md: development setup, PR requirements, project structure
- CHANGELOG.md: backfilled history from 0.1.0 to present
- docs/SECURITY-MODEL.md: threat model, constant-time analysis, zeroization boundaries, RNG, honest limitations
- FIPS 140 vs FIPS 203/204 compliance disclaimer in README
- "Why fips-crypto?" comparison table in README
- Framework integration patterns (Express, Next.js) for `init()`
- Subpackage import documentation for tree-shaking
- FIPS 204 badge

**Testing**
- Property-based tests with fast-check for ML-KEM
- Concurrent initialization safety for `init()` / `initMlKem()` / `initMlDsa()`
- Safeguard tests: cross-algorithm isolation, boundary values, API contract regression
- Script tests: checksum generation/verification, WASM patch, tamper detection
- Auto-init entry point tests
- 567 total tests (up from 324 in 0.4.0), 100% statement/function/line coverage

### Changed
- Package description updated to accurately reflect implemented algorithms (removed premature FIPS 205 claim)
- Coverage thresholds raised to 99/99/97/99 (statements/functions/branches/lines)
- Build scripts use `shx` for cross-platform compatibility (Windows/macOS/Linux)
- README restructured for npm conversion: value proposition first, benchmark data, comparison table
- JSDoc `@example` tags added to all 6 algorithm exports

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
