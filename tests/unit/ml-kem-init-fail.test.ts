/**
 * Tests for WASM initialization failure paths.
 *
 * This test file mocks the WASM module import to simulate a load failure,
 * covering the catch blocks in initMlKem() and initMlDsa().
 */

import { describe, it, expect, vi } from 'vitest';

vi.mock('../../pkg/fips_crypto_wasm.js', () => {
  throw new Error('WASM module not found');
});

describe('WASM initialization failure', () => {
  it('initMlKem throws FipsCryptoError when WASM fails to load', async () => {
    const { initMlKem } = await import('../../src/ml-kem.js');
    await expect(initMlKem()).rejects.toThrow('Failed to load WASM module');
  });

  it('initMlDsa throws FipsCryptoError when WASM fails to load', async () => {
    const { initMlDsa } = await import('../../src/ml-dsa.js');
    await expect(initMlDsa()).rejects.toThrow('Failed to load WASM module');
  });

  it('init throws FipsCryptoError when WASM fails to load', async () => {
    const { init } = await import('../../src/index.js');
    await expect(init()).rejects.toThrow('Failed to load WASM module');
  });

  it('initMlKem can be retried after failure', async () => {
    const { initMlKem } = await import('../../src/ml-kem.js');
    await expect(initMlKem()).rejects.toThrow();
    await expect(initMlKem()).rejects.toThrow();
  });

  it('initMlDsa can be retried after failure', async () => {
    const { initMlDsa } = await import('../../src/ml-dsa.js');
    await expect(initMlDsa()).rejects.toThrow();
    await expect(initMlDsa()).rejects.toThrow();
  });
});
