/**
 * Tests for build scripts (generate-checksums, verify-integrity, patch-wasm).
 *
 * These scripts are .cjs files that run as CLI commands.
 * Tests invoke them as subprocesses and verify behavior.
 */

import { describe, it, expect } from 'vitest';
import { execSync } from 'child_process';
import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';

const ROOT = join(__dirname, '..', '..');

describe('scripts/generate-checksums.cjs', () => {
  it('generates checksums.sha256 in pkg/', () => {
    const checksumPath = join(ROOT, 'pkg', 'checksums.sha256');
    // The build should have already created this
    expect(existsSync(checksumPath)).toBe(true);

    const checksums = JSON.parse(readFileSync(checksumPath, 'utf8'));
    expect(checksums).toHaveProperty('fips_crypto_wasm_bg.wasm');
    expect(checksums).toHaveProperty('fips_crypto_wasm_bg.js');
    expect(checksums).toHaveProperty('fips_crypto_wasm.js');
  });

  it('generates checksums.sha256 in pkg-node/', () => {
    const checksumPath = join(ROOT, 'pkg-node', 'checksums.sha256');
    expect(existsSync(checksumPath)).toBe(true);

    const checksums = JSON.parse(readFileSync(checksumPath, 'utf8'));
    expect(checksums).toHaveProperty('fips_crypto_wasm_bg.wasm');
    expect(checksums).toHaveProperty('fips_crypto_wasm.js');
  });

  it('checksums are valid SHA-256 hex strings (64 chars)', () => {
    const checksumPath = join(ROOT, 'pkg', 'checksums.sha256');
    const checksums = JSON.parse(readFileSync(checksumPath, 'utf8'));

    for (const [, hash] of Object.entries(checksums)) {
      expect(typeof hash).toBe('string');
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    }
  });

  it('checksums match actual file hashes', () => {
    const checksumPath = join(ROOT, 'pkg', 'checksums.sha256');
    const checksums = JSON.parse(readFileSync(checksumPath, 'utf8'));

    for (const [file, expectedHash] of Object.entries(checksums)) {
      const filePath = join(ROOT, 'pkg', file);
      const content = readFileSync(filePath);
      const actualHash = createHash('sha256').update(content).digest('hex');
      expect(actualHash).toBe(expectedHash);
    }
  });

  it('re-running generate-checksums produces same output', () => {
    const checksumPath = join(ROOT, 'pkg', 'checksums.sha256');
    const before = readFileSync(checksumPath, 'utf8');

    execSync('node scripts/generate-checksums.cjs', { cwd: ROOT });

    const after = readFileSync(checksumPath, 'utf8');
    expect(after).toBe(before);
  });
});

describe('scripts/verify-integrity.cjs', () => {
  it('exits 0 when checksums are valid', () => {
    const result = execSync('node scripts/verify-integrity.cjs', {
      cwd: ROOT,
      encoding: 'utf8',
    });
    expect(result).toContain('All checksums verified OK');
    expect(result).toContain('[OK]');
  });

  it('output contains OK for each verified file', () => {
    const result = execSync('node scripts/verify-integrity.cjs', {
      cwd: ROOT,
      encoding: 'utf8',
    });
    expect(result).toContain('[OK]   fips_crypto_wasm_bg.wasm');
    expect(result).toContain('[OK]   fips_crypto_wasm_bg.js');
    expect(result).toContain('[OK]   fips_crypto_wasm.js');
  });

  it('exits 1 when a file has been tampered with', () => {
    const wasmPath = join(ROOT, 'pkg', 'fips_crypto_wasm_bg.wasm');
    const original = readFileSync(wasmPath);

    try {
      // Tamper with the file
      const tampered = Buffer.from(original);
      tampered[0] = tampered[0] ^ 0xFF;
      writeFileSync(wasmPath, tampered);

      // Verify should fail
      let exitCode = 0;
      try {
        execSync('node scripts/verify-integrity.cjs', {
          cwd: ROOT,
          encoding: 'utf8',
          stdio: 'pipe',
        });
      } catch (e) {
        exitCode = (e as { status: number }).status;
      }
      expect(exitCode).toBe(1);
    } finally {
      // Restore original file
      writeFileSync(wasmPath, original);
    }
  });

  it('reports HASH MISMATCH for tampered files', () => {
    const wasmPath = join(ROOT, 'pkg', 'fips_crypto_wasm_bg.wasm');
    const original = readFileSync(wasmPath);

    try {
      const tampered = Buffer.from(original);
      tampered[0] = tampered[0] ^ 0xFF;
      writeFileSync(wasmPath, tampered);

      let output = '';
      try {
        execSync('node scripts/verify-integrity.cjs', {
          cwd: ROOT,
          encoding: 'utf8',
          stdio: 'pipe',
        });
      } catch (e) {
        output = (e as { stdout: string }).stdout || '';
      }
      expect(output).toContain('[FAIL]');
      expect(output).toContain('HASH MISMATCH');
      expect(output).toContain('INTEGRITY CHECK FAILED');
    } finally {
      writeFileSync(wasmPath, original);
    }
  });

  it('skips directories without checksums.sha256', () => {
    // Create a temp dir structure without checksums
    const tmpDir = join(ROOT, 'tmp-test-verify');
    mkdirSync(tmpDir, { recursive: true });

    try {
      // The script checks pkg/ and dist/pkg/ — if we remove dist/pkg checksums temporarily
      const distChecksumPath = join(ROOT, 'dist', 'pkg', 'checksums.sha256');
      let distChecksumBackup: string | null = null;

      if (existsSync(distChecksumPath)) {
        distChecksumBackup = readFileSync(distChecksumPath, 'utf8');
        rmSync(distChecksumPath);
      }

      try {
        const result = execSync('node scripts/verify-integrity.cjs', {
          cwd: ROOT,
          encoding: 'utf8',
        });
        expect(result).toContain('[SKIP]');
      } finally {
        if (distChecksumBackup !== null) {
          writeFileSync(distChecksumPath, distChecksumBackup);
        }
      }
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

describe('scripts/patch-wasm.cjs', () => {
  it('patches Function() pattern in generated JS', () => {
    // Verify the patch was applied during build
    const bgJsPath = join(ROOT, 'pkg', 'fips_crypto_wasm_bg.js');
    const content = readFileSync(bgJsPath, 'utf8');

    // Should NOT contain the original eval-like pattern
    expect(content).not.toContain('return `Function(${name})`;');

    // Should contain the patched version
    expect(content).toContain('return `[Function ${name}]`;');
  });

  it('patch is also applied in dist/pkg/', () => {
    const bgJsPath = join(ROOT, 'dist', 'pkg', 'fips_crypto_wasm_bg.js');
    if (existsSync(bgJsPath)) {
      const content = readFileSync(bgJsPath, 'utf8');
      expect(content).not.toContain('return `Function(${name})`;');
      expect(content).toContain('return `[Function ${name}]`;');
    }
  });
});
