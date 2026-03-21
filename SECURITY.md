# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.5.x   | Yes       |
| < 0.5   | No        |

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
npm run verify:integrity
```

See [README.md](README.md#supply-chain-integrity) for details.
