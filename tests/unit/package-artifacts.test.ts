import { describe, it, expect } from 'vitest';
import { execFileSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';

const ROOT = join(__dirname, '..', '..');

function runNode(script: string): string {
  return execFileSync('node', ['-e', script], {
    cwd: ROOT,
    encoding: 'utf8',
  });
}

describe('published artifact smoke checks', () => {
  it('marks dist/cjs as CommonJS', () => {
    const markerPath = join(ROOT, 'dist', 'cjs', 'package.json');
    expect(existsSync(markerPath)).toBe(true);

    const marker = JSON.parse(readFileSync(markerPath, 'utf8'));
    expect(marker.type).toBe('commonjs');
  });

  it('keeps dist/pkg metadata version aligned with the root package', () => {
    const rootPkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
    const wasmPkg = JSON.parse(readFileSync(join(ROOT, 'dist', 'pkg', 'package.json'), 'utf8'));
    const nodeWasmPkg = JSON.parse(readFileSync(join(ROOT, 'dist', 'pkg-node', 'package.json'), 'utf8'));

    expect(wasmPkg.version).toBe(rootPkg.version);
    expect(nodeWasmPkg.version).toBe(rootPkg.version);
  });

  it('loads the CommonJS build and initializes ML-KEM through pkg-node', () => {
    const output = runNode(`
      (async () => {
        const mod = require('./dist/cjs/index.js');
        await mod.init();
        const { publicKey } = await mod.ml_kem512.keygen(new Uint8Array(64));
        console.log(publicKey.length);
      })().catch((error) => {
        console.error(error);
        process.exit(1);
      });
    `);

    expect(output.trim()).toBe('800');
  });

  it('loads an SLH-DSA small variant from the built ESM artifact', () => {
    const output = runNode(`
      const path = require('path');
      const { pathToFileURL } = require('url');

      (async () => {
        const mod = await import(pathToFileURL(path.join(process.cwd(), 'dist', 'esm', 'index.js')).href);
        await mod.init();
        const { publicKey } = await mod.slh_dsa_sha2_192s.keygen(new Uint8Array(72));
        console.log(publicKey.length);
      })().catch((error) => {
        console.error(error);
        process.exit(1);
      });
    `);

    expect(output.trim()).toBe('48');
  });

  it('ships a published integrity verifier entrypoint', () => {
    const output = execFileSync('node', ['dist/verify-integrity.cjs'], {
      cwd: ROOT,
      encoding: 'utf8',
    });

    expect(output).toContain('All checksums verified OK');
  });
});
