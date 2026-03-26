/**
 * Tests for build scripts (generate-checksums, verify-integrity, patch-wasm).
 *
 * IMPORTANT: Tests that verify tamper detection work on isolated copies of
 * the artifact directories, not the real pkg/ or dist/ trees. This prevents
 * flaky failures when other test files (e.g. package-artifacts.test.ts) read
 * the same files concurrently.
 */

import { describe, it, expect } from 'vitest';
import { execSync } from 'child_process';
import { readFileSync, writeFileSync, existsSync, rmSync, cpSync } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';

const ROOT = join(__dirname, '..', '..');

/**
 * Verify checksums in a given directory. Returns { ok, output }.
 * This avoids shelling out to verify-integrity.cjs (which uses __dirname)
 * and lets us point at an isolated temp copy for tamper tests.
 */
function verifyDir(dirPath: string): { ok: boolean; output: string } {
  const checksumPath = join(dirPath, 'checksums.sha256');
  if (!existsSync(checksumPath)) {
    return { ok: true, output: `[SKIP] checksums.sha256 not found` };
  }
  const checksums = JSON.parse(readFileSync(checksumPath, 'utf8'));
  const lines: string[] = [];
  let hasErrors = false;

  for (const [file, expectedHash] of Object.entries(checksums)) {
    const filePath = join(dirPath, file);
    if (!existsSync(filePath)) {
      lines.push(`[FAIL] ${file}: FILE MISSING`);
      hasErrors = true;
      continue;
    }
    const actual = createHash('sha256').update(readFileSync(filePath)).digest('hex');
    if (actual === expectedHash) {
      lines.push(`[OK]   ${file}`);
    } else {
      lines.push(`[FAIL] ${file}: HASH MISMATCH`);
      lines.push(`       expected: ${expectedHash}`);
      lines.push(`       actual:   ${actual}`);
      hasErrors = true;
    }
  }
  if (hasErrors) {
    lines.push('INTEGRITY CHECK FAILED');
  }
  return { ok: !hasErrors, output: lines.join('\n') };
}

describe('scripts/generate-checksums.cjs', () => {
  it('generates checksums.sha256 in pkg/', () => {
    const checksumPath = join(ROOT, 'pkg', 'checksums.sha256');
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

  // Tamper-detection tests run against isolated copies to avoid flaky
  // interactions with other test files reading pkg/ concurrently.
  it('detects tampered file (exits non-zero)', () => {
    const tmpDir = join(ROOT, 'tmp-tamper-test-exit');
    try {
      cpSync(join(ROOT, 'pkg'), tmpDir, { recursive: true });

      const wasmPath = join(tmpDir, 'fips_crypto_wasm_bg.wasm');
      const tampered = Buffer.from(readFileSync(wasmPath));
      tampered[0] ^= 0xff;
      writeFileSync(wasmPath, tampered);

      const { ok } = verifyDir(tmpDir);
      expect(ok).toBe(false);
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('reports HASH MISMATCH for tampered files', () => {
    const tmpDir = join(ROOT, 'tmp-tamper-test-mismatch');
    try {
      cpSync(join(ROOT, 'pkg'), tmpDir, { recursive: true });

      const wasmPath = join(tmpDir, 'fips_crypto_wasm_bg.wasm');
      const tampered = Buffer.from(readFileSync(wasmPath));
      tampered[0] ^= 0xff;
      writeFileSync(wasmPath, tampered);

      const { output } = verifyDir(tmpDir);
      expect(output).toContain('[FAIL]');
      expect(output).toContain('HASH MISMATCH');
      expect(output).toContain('INTEGRITY CHECK FAILED');
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('skips directories without checksums.sha256', () => {
    const tmpDir = join(ROOT, 'tmp-tamper-test-skip');
    try {
      cpSync(join(ROOT, 'pkg'), tmpDir, { recursive: true });
      rmSync(join(tmpDir, 'checksums.sha256'));

      const { output } = verifyDir(tmpDir);
      expect(output).toContain('[SKIP]');
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

describe('scripts/patch-wasm.cjs', () => {
  const UNSAFE = 'return `Function(${name})`;';
  const SAFE   = 'return `[Function ${name}]`;';

  it('no eval-like pattern in pkg/ JS files (bundler target)', () => {
    const bgJs = join(ROOT, 'pkg', 'fips_crypto_wasm_bg.js');
    const content = readFileSync(bgJs, 'utf8');
    expect(content).not.toContain(UNSAFE);
    expect(content).toContain(SAFE);
  });

  it('no eval-like pattern in pkg-node/ JS files (nodejs target)', () => {
    const nodeJs = join(ROOT, 'pkg-node', 'fips_crypto_wasm.js');
    const content = readFileSync(nodeJs, 'utf8');
    expect(content).not.toContain(UNSAFE);
    expect(content).toContain(SAFE);
  });

  it('no eval-like pattern in dist/pkg/ (published bundler artifact)', () => {
    const bgJs = join(ROOT, 'dist', 'pkg', 'fips_crypto_wasm_bg.js');
    if (existsSync(bgJs)) {
      const content = readFileSync(bgJs, 'utf8');
      expect(content).not.toContain(UNSAFE);
    }
  });

  it('no eval-like pattern in dist/pkg-node/ (published nodejs artifact)', () => {
    const nodeJs = join(ROOT, 'dist', 'pkg-node', 'fips_crypto_wasm.js');
    if (existsSync(nodeJs)) {
      const content = readFileSync(nodeJs, 'utf8');
      expect(content).not.toContain(UNSAFE);
    }
  });

  it('re-running patch-wasm is idempotent', () => {
    const nodeJs = join(ROOT, 'pkg-node', 'fips_crypto_wasm.js');
    const before = readFileSync(nodeJs, 'utf8');

    execSync('node scripts/patch-wasm.cjs', { cwd: ROOT });

    const after = readFileSync(nodeJs, 'utf8');
    expect(after).toBe(before);
  });

  it('embeds a WASM integrity check in pkg-node/ loader', () => {
    const nodeJs = join(ROOT, 'pkg-node', 'fips_crypto_wasm.js');
    const content = readFileSync(nodeJs, 'utf8');
    expect(content).toContain('__expectedHash');
    expect(content).toContain('WASM integrity check failed');
  });

  it('embedded hash matches the actual WASM binary', () => {
    const nodeJs = join(ROOT, 'pkg-node', 'fips_crypto_wasm.js');
    const content = readFileSync(nodeJs, 'utf8');
    const match = content.match(/const __expectedHash = '([a-f0-9]{64})'/);
    expect(match).not.toBeNull();
    const embeddedHash = match![1];

    const wasmPath = join(ROOT, 'pkg-node', 'fips_crypto_wasm_bg.wasm');
    const wasmBytes = readFileSync(wasmPath);
    const actualHash = createHash('sha256').update(wasmBytes).digest('hex');
    expect(actualHash).toBe(embeddedHash);
  });

  // Tamper test runs against an isolated copy of pkg-node/.
  it('tampered WASM binary is rejected at load time', () => {
    const tmpDir = join(ROOT, 'tmp-tamper-test-wasm');
    try {
      cpSync(join(ROOT, 'pkg-node'), join(tmpDir, 'pkg-node'), { recursive: true });

      const wasmPath = join(tmpDir, 'pkg-node', 'fips_crypto_wasm_bg.wasm');
      const tampered = Buffer.from(readFileSync(wasmPath));
      tampered[0] ^= 0xff;
      writeFileSync(wasmPath, tampered);

      let threw = false;
      try {
        execSync(`node -e "require('./pkg-node/fips_crypto_wasm.js')"`, {
          cwd: tmpDir,
          encoding: 'utf8',
          stdio: 'pipe',
        });
      } catch (e) {
        threw = true;
        const stderr = (e as { stderr: string }).stderr || '';
        expect(stderr).toContain('WASM integrity check failed');
      }
      expect(threw).toBe(true);
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
