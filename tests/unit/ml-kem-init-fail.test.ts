/**
 * Tests for WASM initialization failure path.
 *
 * This test file mocks the WASM module import to simulate a load failure,
 * covering the catch block in initMlKem().
 */

import { describe, it, expect, vi } from 'vitest';

vi.mock('../../pkg/fips_crypto_wasm.js', () => {
  throw new Error('WASM module not found');
});

describe('ML-KEM WASM initialization failure', () => {
  it('initMlKem throws FipsCryptoError when WASM fails to load', async () => {
    const { initMlKem } = await import('../../src/ml-kem.js');
    await expect(initMlKem()).rejects.toThrow('Failed to load WASM module');
  });

  it('init throws FipsCryptoError when WASM fails to load', async () => {
    const { init } = await import('../../src/index.js');
    await expect(init()).rejects.toThrow('Failed to load WASM module');
  });

  it('initMlKem can be retried after failure', async () => {
    const { initMlKem } = await import('../../src/ml-kem.js');
    // First attempt fails
    await expect(initMlKem()).rejects.toThrow();
    // Second attempt should also fail (not stuck in pending state)
    await expect(initMlKem()).rejects.toThrow();
  });
});
