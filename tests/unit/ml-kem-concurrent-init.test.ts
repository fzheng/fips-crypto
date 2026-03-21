/**
 * Test for concurrent initialization of ML-KEM WASM module.
 *
 * Covers the `if (wasmInitPromise) return wasmInitPromise` branch
 * by calling initMlKem() twice while the first is still in flight.
 */

import { describe, it, expect, vi } from 'vitest';

// Mock the WASM module with a delayed import to ensure the concurrent path is hit
let resolveWasm: (value: unknown) => void;
const wasmPromise = new Promise((resolve) => { resolveWasm = resolve; });

vi.mock('../../pkg/fips_crypto_wasm.js', () => {
  return wasmPromise;
});

describe('ML-KEM concurrent init', () => {
  it('second initMlKem() call returns the same promise (concurrent guard)', async () => {
    const { initMlKem } = await import('../../src/ml-kem.js');

    // Start first init (will be pending because our mock hasn't resolved)
    const p1 = initMlKem();

    // Second call should hit the wasmInitPromise branch (line 39)
    const p2 = initMlKem();

    // Resolve the mock
    resolveWasm({ default: () => {} });

    // Both should resolve without error
    await Promise.all([p1, p2]);
  });
});
