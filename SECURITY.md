# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| 0.7.x   | Yes       |
| < 0.7   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in fips-crypto, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **GitHub Security Advisory** (preferred): Use [GitHub's private security advisory feature](https://github.com/fzheng/fips-crypto/security/advisories/new) to report the issue confidentially.

2. **Email**: Contact the maintainer directly via the email associated with the [GitHub profile](https://github.com/fzheng).

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact assessment

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Fix or mitigation**: Depends on severity, targeting:
  - Critical: 48 hours
  - High: 7 days
  - Medium/Low: Next release cycle

### Scope

The following are considered in-scope for security reports:

- **Cryptographic correctness**: Incorrect algorithm output that deviates from FIPS 203/204 specifications
- **Side-channel leaks**: Timing or other observable differences that leak secret key material
- **Supply chain tampering**: Modifications to published WASM binaries or JS bindings not matching source
- **Memory safety**: Issues in the Rust/WASM boundary that could leak or corrupt secret data

### Out of Scope

- Denial of service via large inputs (expected behavior for cryptographic operations)
- Issues in development dependencies not affecting the published package
- Theoretical quantum attacks (these algorithms are designed to resist them)

## Supply Chain Verification

Every published release includes SHA-256 checksums for all WASM and JS binding files. Verify package integrity after installation:

```bash
npx fips-crypto-verify-integrity

# Or from the package directory itself
npm run verify:integrity
```

See [README.md](README.md#supply-chain-integrity) for details.

## Verifying Package Provenance

fips-crypto is published with [npm provenance](https://docs.npmjs.com/generating-provenance-statements), linking each release to a specific GitHub Actions workflow run via Sigstore attestation.

### Verify with npm CLI (v9.5.0+)

```bash
npm audit signatures
```

A successful result confirms the package was built and published by the GitHub Actions workflow in the `fzheng/fips-crypto` repository, not by a compromised token or third party.

### What each verification layer protects against

| Threat | Checksums | Provenance |
|--------|-----------|------------|
| CDN/mirror corruption | Yes | No |
| Stolen npm token | No | Yes |
| Compromised CI environment | No | No |

For a detailed security model, see [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md#checksums-vs-provenance-threat-boundaries).
